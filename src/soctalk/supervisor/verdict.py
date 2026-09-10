"""Verdict node using reasoning LLM for final decision."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from langchain_core.messages import HumanMessage
import structlog

from soctalk.authorization.render import verdict_authorization_detail
from soctalk.config import get_config
from soctalk.inference import (
    InferenceAccounting,
    InferenceRequest,
    InferenceTier,
    ainvoke_request,
    resolve_tier_sampling,
)
from soctalk.llm import classify_llm_error as _classify_llm_error
from soctalk.models.enums import Phase, VerdictDecision
from soctalk.models.verdict import Verdict, VerdictDraft

logger = structlog.get_logger()


VERDICT_SYSTEM_PROMPT = r"""You are a Principal Security Analyst providing final verdict on a security investigation.

Your role is to critically evaluate all evidence and make a final recommendation before human review.

## Your Task (OODA Framework)

1. **Observe (Host & SIEM Telemetry)**: Review Wazuh alert metadata, agent process hierarchy (`get_wazuh_agent_processes`), and listening ports (`get_wazuh_agent_ports`).
2. **Orient (Threat Intelligence & Attribution)**: Correlate multi-source reputation — VirusTotal detection ratios/hashes, AbuseIPDB confidence scores, and MISP threat actor links.
3. **Evaluate Evidence Quality**: Is the telemetry conclusive, circumstantial, or false alarm noise?
4. **Consider Alternatives & Authorization**: Cross-reference authorization context (change tickets, maintenance windows, administrative baselines).
5. **Decide & Act**: Deliver the formal SOP verdict and populate production-ready Jira ticket fields.

## Challenge Assumptions

- What assumptions are being made?
- Is the confidence level justified by the evidence?
- Are there red flags being overlooked?
- Could benign activities explain these indicators?

## Authorization Reasoning (when an Authorization Context section is present)

Decide whether the activity was AUTHORIZED, not just whether it looks unusual. Close requires
ALL FOUR to hold: (1) sanctioned-or-routine — an approving record of the right kind (change
ticket, standing baseline, or established routine history) names this activity; (2) in-scope —
a SINGLE record fully covers it: right subject, target, action, time window, calendar validity,
CAB approval if required, not blocked by an active freeze. Never combine two partial records.
Expired, pending, future-effective, unapproved-CAB, out-of-window, wrong-host/account/path
records do NOT cover, no matter how official they look; (3) actor/target genuine — not
compromised or contained, no service account used interactively, no off-call privileged human;
(4) policy-allowed — no high-priority policy forbids it without a waiver or a covering
break-glass emergency change.

Distinguish ABSENT evidence from CONTRADICTED evidence — they call for different decisions:
- ABSENT: the context carries no authorization records at all for this activity. Never treat
  absence as implicit approval; when the case hinges on authorization and evidence is genuinely
  missing, prefer needs_more_info over close.
- CONTRADICTED: authorization records ARE present but fail to cover — expired, pending,
  future-effective, CAB-unapproved, out-of-window, frozen, or scoped to a different
  host/account/path. That mismatch is itself the finding: someone acted outside the terms of
  their authorization. ESCALATE. Do not choose needs_more_info to "verify the discrepancy" —
  the discrepancy is the signal, and a human incident responder is the right verifier.

Authorization evidence lowers suspicion; it NEVER overrides malicious indicators, IOC matches,
or active-incident correlation.

## Decision Options & SOP Verdict Mapping (Tier-3 Evaluation Hierarchy)

Select both the internal routing `decision` and the formal `sop_verdict` using this strict sequential order:

### PRIORITY 0: DECEPTION CANARY PRE-EMPTION GATE (Evaluate First)
- **Trigger:** If `originating_process` or alert telemetry matches deception services (`ZADService.exe`, `landmine.exe`, `attivo`), decoy bait strings (`CLOP#`, `EKANS`), or canary paths:
  - **Verdict:** Strictly `True Positive – Benign / Expected` (mapped to `sop_verdict: "False Positive - Benign Software"` / `decision: "close"`).
  - **Severity:** Strictly `Low` (`10031`).
  - **HALT VERDICT EVALUATION.** Do not classify as Policy Violation or Malicious.

### RULE A: TENANT POLICY & USER-DEFINED BLOCKLIST GATE
- **Trigger:** Engine is `User-Defined Blocklist`, `user_blacklist`, rule policy block, or unapproved commercial utility (`wps.exe`, `AnyDesk.exe`, torrent clients):
  - **ABSOLUTE VT DOWNGRADE PROHIBITION:** STRICTLY FORBIDDEN from classifying as False Positive due to clean VirusTotal ratios (**0/70**). Blocklists are administrative policy directives, not EDR misidentifications.
  - **Verdict:** Strictly `sop_verdict: "True Positive - Policy Violation"` (`decision: "escalate"`).
  - **Severity:** `Medium` (`10030`) or `High` (`10029`) if executed from user paths; `Low` (`10031`) if dormant on disk.
  - **STOP HERE.** Do not proceed to Rule C.

### RULE B: CONFIRMED MALICIOUS / TRUE POSITIVE (MALWARE PAYLOADS)
- **Trigger:** Confirmed malware, ransomware, weaponized exploits, active C2 beaconing, credential dumping, or software cracks (`Patch.exe`):
  - **Verdict:** Strictly `sop_verdict: "True Positive - Malicious"` (`decision: "escalate"`).
  - **Severity:** `Critical` (`10028`) if unmitigated or active C2; `High` (`10029`) if neutralized/mitigated.
  - **PROHIBITION:** NEVER ask the customer if confirmed malware was "authorized".

### RULE C: FALSE POSITIVE (BENIGN ENTERPRISE BASELINE)
- **Trigger:** Legitimate enterprise application verified by ALL: (1) valid digital signature, (2) standard installation path (`\Program Files\`), (3) clean threat intelligence (**0/70 clean** or isolated non-consensus heuristic **1/70**), (4) not a blocklist match, (5) zero post-execution behavioral indicator events in host telemetry.
  - **Verdict:** Strictly `sop_verdict: "False Positive - Benign Software"` (`decision: "close"`).
  - **Severity:** Strictly `Low` (`10031`).

### RULE D: VALIDATION REQUIRED (AMBIGUOUS DUAL-USE TOOLS)
- **Trigger:** Ambiguous administrative utilities or native maintenance scripts executed without confirmed malicious indicators where business authorization is unknown:
  - **Verdict:** Strictly `sop_verdict: "Validation Required - Suspicious"` (`decision: "needs_more_info"` or `"escalate"`).
  - **Severity:** `Medium` (`10030`) for 3rd-party tools; `Low` (`10031`) for native scripts.

## Report Formatting Requirements (in `recommendation` field)

Structure your `recommendation` string using this exact 3-part Markdown format:

### PART 1: ALERT DETAILS
- Primary Rule ID, Description, and Severity Level
- Affected Asset / Endpoint (or Perimeter Device if Agent 000)
- Key Network & User Observables (Source/Dest IP, Ports, Account)

### PART 2: ANALYSIS & IMPACT
- Root Cause & Forensic Findings (Payload Analysis, Process Lineage, Threat Intel)
- Perimeter & Host Disposition (e.g. Connection dropped by firewall, active execution)
- Blast Radius & Impact Assessment

### PART 3: RECOMMENDATIONS & REMEDIATION PLAN
- Immediate Containment Steps (with executable firewall / host isolation commands)
- Eradication & Verification Steps
- Indicator Blocking & Tuning Recommendations

## Response Format

Provide your verdict with these fields:
- decision: "escalate" | "close" | "needs_more_info"
- sop_verdict: "True Positive – Malicious" | "True Positive – Benign / Expected" | "False Positive" | "Validation Required"
- confidence: 0.0-1.0
- threat_assessment: Overall assessment of the threat
- evidence_strength: "weak" | "moderate" | "strong" | "conclusive"
- potential_impact: "low" | "medium" | "high" | "critical"
- urgency: "routine" | "elevated" | "urgent" | "immediate"
- key_evidence: List of key evidence points
- gaps_in_evidence: What's missing
- assumptions_made: Assumptions in your analysis
- alternative_explanations: Benign explanations considered
- recommendation: Complete 3-Part Markdown formatted report and action plan
- additional_investigation_needed: (if needs_more_info) What specific investigation is needed

# Additionally populate these Jira-oriented fields (used verbatim by the reporter):
- threat_title: Short title in format: "NopalCyber SOC Alert | <Threat Name> Detected on <Hostname> | <Severity>"
- threat_description: Customer-facing text starting with the Hi Team intro and the structured Threat Overview table. Follow the Selective Backtick Rule (never backtick verdicts, statuses, scores, or dates).
- impact_for_you: Concise "Analysis & Impact" text. ZERO HEADINGS OR LABELS ALLOWED. Output strictly as EXACTLY 5 plain bullet points (`- `):
  1. File Assessment: File name, full path, SHA-256, digital signature status, and bold VirusTotal ratio (**0/70 clean** or **3/62 detections (Vendor: Sig)**).
  2. Process Lineage Chain: Dynamic execution chain using `<Originating_Parent> → <Suspect_Process> → <Spawned_Children>` with execution security context (`SYSTEM` vs user).
  3. Storyline & Mitigation: Real-time host containment declaration (`Mitigated` vs `Not Mitigated`) and itemized API/DLL artifacts observed.
  4. Persistence & Lateral Movement: Confirmed registry run keys, services, tasks, or standard OS caching statement if confined to BAM/AppCompat.
  5. Network Sockets & C2: Destination public IP, port, and AbuseIPDB score. If zero sockets exist, state strictly: "No external command-and-control (C2) communication or process-bound network traffic was established by this process." (Print ZERO IP addresses).
- remediation_steps: 2–3 customer-facing actionable bullet points for Jira `remediation_steps`. Lead with an assertive finding for malware, administrative software removal for policy violations, and tuning for false positives. Do NOT include "monitor" or open-ended observation tasks.

## Device Health Determination Matrix
- **Healthy:** When Verdict is `False Positive - Benign Software`, OR when Verdict is `True Positive - Policy Violation` and `Threat Status` is `Mitigated`, OR when `True Positive - Malicious` is neutralized (`Quarantined`/`Killed`/`Blocked`) with zero secondary persistence.
- **Infected:** When `True Positive - Malicious` and `Threat Status` is `Not Mitigated`, OR active secondary malware processes/persistence remain active on host.
- **Under Investigation:** When Verdict is `Validation Required - Suspicious` OR `Threat Status` is `Pending`.

Populate the `recommendation` field strictly with the human-readable 3-Part Markdown report (Alert Details, Analysis & Impact, Recommendations & Remediation Plan). Do NOT embed raw JSON inside `recommendation`.

In parallel, populate the discrete Jira fields (`threat_title`, `threat_description`, `impact_for_you`, `remediation_steps`) directly on the output schema. Map custom field IDs accordingly:
- `customfield_10044` (Severity): 10028=Critical, 10029=High, 10030=Medium, 10031=Low
- `customfield_10220` (Analyst Verdict): 10329=True Positive (Malicious/Policy Violation), 10327=False Positive, 10336=Validation Required
- `customfield_10303` (Threat Category): 10840=Unauthorized Activity (Policy Violations/Blocklists), 10862=Authorized Application (FP), 10830=Malware
- `customfield_10534` (Top Level Category): 10995=Apps (Commercial utilities/blocklists), 10994=Malware (Confirmed payloads)
"""

# Ordered most-static -> most-variable: alert evidence first, per-run
# metadata (ID, wall-clock duration, iteration count) at the tail so the
# prompt shares the longest possible cacheable prefix with the supervisor
# calls that preceded it in the same investigation.
VERDICT_USER_PROMPT_TEMPLATE = """## Alerts ({alert_count})

{alerts_detail}

## Threat Intelligence Results ({enrichment_count})

{enrichments_detail}

## Findings ({finding_count})

{findings_detail}

{authorization_detail}## Supervisor's Assessment

**Last Action:** {supervisor_action}
**TP Confidence:** {supervisor_confidence:.0%}
**Reasoning:** {supervisor_reasoning}

## Run Metadata

**Investigation ID:** {investigation_id}
**Duration:** {duration}
**Supervisor Iterations:** {iterations}

---

Provide your final verdict.
"""


async def verdict_node(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Verdict node - reasoning LLM provides final decision.

    This node uses an advanced reasoning model to:
    1. Critically evaluate all evidence
    2. Challenge assumptions
    3. Make final escalate/close/needs_more_info decision

    Args:
        state: Current graph state.

    Returns:
        Updated state with verdict.
    """
    logger.info("verdict_node_started")

    app_config = get_config()

    try:
        # Build comprehensive context
        context = _build_verdict_context(state)

        # Get verdict from reasoning LLM
        verdict = await _get_verdict(app_config, context, state)

        state["verdict"] = verdict.model_dump()
        state["current_phase"] = Phase.VERDICT.value

        # Track retry count for NEEDS_MORE_INFO decisions
        if verdict.decision == VerdictDecision.NEEDS_MORE_INFO:
            state["verdict_retry_count"] = state.get("verdict_retry_count", 0) + 1
            logger.info(
                "verdict_needs_more_info",
                retry_count=state["verdict_retry_count"],
            )

        logger.info(
            "verdict_rendered",
            decision=verdict.decision.value,
            sop_verdict=verdict.sop_verdict.value if verdict.sop_verdict else None,
            confidence=verdict.confidence,
            impact=verdict.potential_impact.value,
        )

    except Exception as e:
        # Classify so the worker can route LLM-provider failures
        # (credit lack, rate limit, transient 5xx) to ``failed`` status
        # rather than a fake escalated verdict — those errors carry the
        # raw API response string which would otherwise become the
        # user-facing HIL review description (real incident from
        # 2026-05). Anthropic / OpenAI errors all hand us a
        # ``status_code`` attribute via the langchain wrapper.
        category = _classify_llm_error(e)
        logger.error(
            "verdict_node_error",
            error=str(e)[:200],
            category=category,
        )
        state["verdict_error"] = {
            "category": category,
            # Full string kept in state for operator debugging in logs
            # only — the worker MUST NOT propagate this into any
            # user-facing field (verdict_summary, pending_reviews.desc).
            "message": str(e)[:500],
        }
        state["last_error"] = f"verdict_failed:{category}"
        # Track retry so the supervisor's max_retries gate fires; the
        # graph keeps running for transient categories but ``verdict``
        # is NOT populated — the worker treats missing verdict as a
        # failed run.
        state["verdict_retry_count"] = state.get("verdict_retry_count", 0) + 1

    state["last_updated"] = datetime.now().isoformat()
    return state


def _build_verdict_context(state: dict[str, Any]) -> dict[str, Any]:
    """Build comprehensive context for verdict LLM.

    Args:
        state: Current state.

    Returns:
        Context dictionary for prompt formatting.
    """
    investigation = state.get("investigation", {})
    alerts = investigation.get("alerts", [])
    enrichments = investigation.get("enrichments", [])
    findings = investigation.get("findings", [])
    supervisor_decision = state.get("supervisor_decision", {})

    # Format alerts. Cap the render (issue #26 correlation can put many
    # alerts on one investigation) so a large correlated group doesn't blow
    # up the verdict prompt; alerts arrive severity-ordered so the cap keeps
    # the most severe, with an explicit overflow marker.
    _VERDICT_ALERT_CAP = 10
    alerts_lines = []
    for alert in alerts[:_VERDICT_ALERT_CAP]:
        if hasattr(alert, "model_dump"):
            alert = alert.model_dump()
        severity = alert.get("severity", "unknown")
        desc = alert.get("rule_description", "No description")
        agent_data = alert.get("source", {})
        agent = agent_data.get("agent_name", "unknown") if isinstance(agent_data, dict) else "unknown"
        level = alert.get("level", 0)
        timestamp = alert.get("timestamp", "unknown")

        alerts_lines.append(f"### [{severity.upper()}] Level {level}")
        alerts_lines.append(f"**Description:** {desc}")
        alerts_lines.append(f"**Agent:** {agent}")
        alerts_lines.append(f"**Time:** {timestamp}")
        alerts_lines.append("")
    if len(alerts) > _VERDICT_ALERT_CAP:
        alerts_lines.append(
            f"... and {len(alerts) - _VERDICT_ALERT_CAP} more correlated alerts "
            f"(showing the {_VERDICT_ALERT_CAP} most severe)"
        )
        alerts_lines.append("")

    # Format enrichments with safe model/dict unwrapping
    enrichments_lines = []
    malicious_count = 0
    suspicious_count = 0

    for e in enrichments:
        if hasattr(e, "model_dump"):
            e = e.model_dump()

        verdict_raw = e.get("verdict", "unknown")
        verdict_val = str(getattr(verdict_raw, "value", verdict_raw)).lower()

        obs = e.get("observable", {})
        if hasattr(obs, "model_dump"):
            obs = obs.model_dump()

        value = obs.get("value", "unknown") if isinstance(obs, dict) else str(obs)
        obs_type = obs.get("type", "unknown") if isinstance(obs, dict) else "observable"
        analyzer = e.get("analyzer", "VirusTotal")
        confidence = e.get("confidence", 0)

        if "malicious" in verdict_val:
            malicious_count += 1
            emoji = "🔴"
        elif "suspicious" in verdict_val:
            suspicious_count += 1
            emoji = "⚠️"
        elif "benign" in verdict_val or "clean" in verdict_val:
            emoji = "✅"
        else:
            emoji = "❓"

        enrichments_lines.append(
            f"{emoji} **{obs_type}:** {value}\n"
            f"   Analyzer: {analyzer} | Verdict: {verdict_val} | Confidence: {confidence:.0%}"
        )

    enrichments_lines.insert(0, f"**Summary:** {malicious_count} malicious, {suspicious_count} suspicious\n")

    # Format findings
    findings_lines = []
    for f in findings:
        if hasattr(f, "model_dump"):
            f = f.model_dump()

        if isinstance(f, dict):
            severity = f.get("severity", "unknown")
            desc = f.get("description", "No description")
            evidence = f.get("evidence", [])
        else:
            severity = "info"
            desc = str(f)
            evidence = []

        findings_lines.append(f"### [{severity.upper()}] {desc}")
        if evidence:
            findings_lines.append("Evidence:")
            for ev in evidence[:3]:
                findings_lines.append(f"  - {ev}")
        findings_lines.append("")

    # Calculate duration safely
    started_at = state.get("started_at")
    if started_at:
        if isinstance(started_at, str):
            try:
                started_at = datetime.fromisoformat(started_at)
            except Exception:
                started_at = None
        if started_at is not None:
            now = (
                datetime.now(started_at.tzinfo)
                if started_at.tzinfo is not None
                else datetime.now()
            )
            duration = now - started_at
            duration_str = f"{duration.total_seconds():.0f} seconds"
        else:
            duration_str = "unknown"
    else:
        duration_str = "unknown"

    return {
        "investigation_id": investigation.get("id", "unknown"),
        "duration": duration_str,
        "iterations": state.get("iteration_count", 0),
        "alert_count": len(alerts),
        "alerts_detail": "\n".join(alerts_lines) if alerts_lines else "No alerts",
        "enrichment_count": len(enrichments),
        "enrichments_detail": "\n".join(enrichments_lines) if enrichments_lines else "No enrichments",
        "finding_count": len(findings),
        "findings_detail": "\n".join(findings_lines) if findings_lines else "No findings",
        "authorization_detail": verdict_authorization_detail(investigation),
        "supervisor_action": supervisor_decision.get("next_action", "unknown"),
        "supervisor_confidence": supervisor_decision.get("tp_confidence", 0.5),
        "supervisor_reasoning": supervisor_decision.get("confidence_reasoning", "No reasoning"),
    }


async def _get_verdict(
    config: Any,
    context: dict[str, Any],
    state: dict[str, Any] | None = None,
) -> Verdict:
    """Get verdict from reasoning LLM.

    Args:
        config: Application configuration.
        context: Context dictionary.
        state: Optional state dictionary for inference accounting.

    Returns:
        Verdict object.
    """
    # Reasoning tier (more capable) via the single ainvoke_request seam (#32).
    req = InferenceRequest(
        tier=InferenceTier.REASONING,
        metadata=InferenceAccounting(producer="supervisor.verdict", budget_state=state),
        output_schema=VerdictDraft,
        system=VERDICT_SYSTEM_PROMPT,
        messages=[HumanMessage(content=VERDICT_USER_PROMPT_TEMPLATE.format(**context))],
        sampling=resolve_tier_sampling(
            config.llm, InferenceTier.REASONING, temperature=0.1, max_tokens=4096,
        ),
    )
    res = await ainvoke_request(req, cfg=config.llm)
    draft = res.parsed
    return Verdict(
        **draft.model_dump(),
        reasoning_model=res.resolved.model,
    )


