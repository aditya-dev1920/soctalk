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


VERDICT_SYSTEM_PROMPT = """You are a Principal Security Analyst providing final verdict on a security investigation.

Your role is to critically evaluate all evidence and make a final recommendation before human review.

## Your Task

1. **Evaluate Evidence Quality**: Is the evidence conclusive, circumstantial, or weak?
2. **Consider Alternatives**: Could this be legitimate activity? What would that look like?
3. **Assess Attack Coherence**: If malicious, does the activity tell a coherent attack story?
4. **Identify Gaps**: What evidence is missing that would strengthen/weaken the case?
5. **Risk Calculus**: What's the cost of a false positive vs false negative?

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

## Decision Options & SOP Verdict Mapping

Select both the internal routing `decision` and the formal `sop_verdict`:

1. **True Positive – Malicious** (`decision: "escalate"`):
   - Confirmed malicious activity or unmitigated high-risk exploit/C2 attempt.
2. **True Positive – Benign / Expected** (`decision: "escalate"` or `"close"`):
   - Legitimate administrative script, authorized security test, or approved change.
3. **False Positive** (`decision: "close"`):
   - Rule misfire, benign system noise, or known non-malicious signature trigger.
4. **Validation Required** (`decision: "needs_more_info"` or `"escalate"`):
   - Ambiguous activity needing asset owner or user verification.

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
- threat_title: Short title for the Jira `threat_title` field (e.g. "NopalCyber SOC Alert | Patch.exe Detected on HOST1 | High")
- threat_description: Customer-facing short threat description for Jira `threat_description` (starts with the Hi Team intro and the Threat Overview table — must NOT include Analysis or Recommendations)
- impact_for_you: Concise "Analysis & Impact" text for Jira `impact_for_you` formatted as five fixed sections **(File Analysis, Process & Command-Line Analysis, Storyline Analysis, Persistence & Lateral Movement Analysis, Network Analysis)**. Each section must be bolded (plain text, not header) and followed by 1–2 bullet points. Avoid vendor or product names — use neutral terms like "reputation sources" or "reputation checks".
- remediation_steps: 2–3 customer-facing actionable bullet points for Jira `remediation_steps`. Do NOT include "monitor" or open-ended observation tasks.

Refer to the Jira ticket schema at `docs/jira_template.json` and emit a JSON object matching the required keys when producing the `recommendation` section used for automated reporting. The worker expects keys: `summary`, `threat_title`, `threat_description`, `impact_for_you`, `remediation_steps`, `customfield_10044`, `customfield_10220`, `project`, `issue_type`.
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


