"""Close investigation node."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from soctalk.models.enums import HumanDecision, InvestigationStatus, Phase, VerdictDecision

logger = structlog.get_logger()


async def close_investigation_node(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Close investigation node.

    Finalizes the investigation with appropriate status and closure reason.

    Args:
        state: Current graph state.

    Returns:
        Updated state with closed investigation.
    """
    logger.info("closing_investigation")

    investigation = state.get("investigation", {})
    verdict = state.get("verdict", {})
    human_decision = state.get("human_decision")
    human_feedback = state.get("human_feedback")
    supervisor_decision = state.get("supervisor_decision", {})
    is_operational_close = state.get("operational_close", False)

    # Determine closure reason and status
    closure_reason = _determine_closure_reason(
        verdict=verdict,
        human_decision=human_decision,
        human_feedback=human_feedback,
        supervisor_decision=supervisor_decision,
        is_operational_close=is_operational_close,
    )

    now_iso = datetime.now(timezone.utc).isoformat()

    # Update investigation status
    investigation["status"] = InvestigationStatus.CLOSED.value
    investigation["closed_at"] = now_iso
    investigation["closure_reason"] = closure_reason

    # Log closure details
    logger.info(
        "investigation_closed",
        investigation_id=investigation.get("id"),
        closure_reason=closure_reason[:100],
        human_decision=human_decision,
        verdict_decision=verdict.get("decision") if verdict else None,
        sop_verdict=verdict.get("sop_verdict") if verdict else None,
    )

    state["investigation"] = investigation
    # Enter reporting/escalation phase so downstream workers (e.g. Jira) run next
    state["current_phase"] = Phase.ESCALATION.value
    state["last_updated"] = now_iso

    return state


def _determine_closure_reason(
    verdict: dict[str, Any],
    human_decision: str | Any | None,
    human_feedback: str | None,
    supervisor_decision: dict[str, Any],
    is_operational_close: bool = False,
) -> str:
    """Determine the closure reason based on various factors.

    Args:
        verdict: Verdict from reasoning LLM.
        human_decision: Decision from human review.
        human_feedback: Feedback from human review.
        supervisor_decision: Decision from supervisor.
        is_operational_close: Whether closed via deterministic triage policy.

    Returns:
        Closure reason string.
    """
    reasons: list[str] = []

    # 1. Check deterministic operational triage policy close
    if is_operational_close:
        reasons.append("Closed by deterministic triage policy - operational alert class with no security indicators")
        return " | ".join(reasons)

    # 2. Check human review decision
    if human_decision:
        h_dec = str(getattr(human_decision, "value", human_decision or "")).lower()
        if h_dec == HumanDecision.REJECT.value.lower():
            reasons.append("Rejected by analyst during human review")
            if human_feedback:
                reasons.append(f"Analyst feedback: {human_feedback}")
        elif h_dec == HumanDecision.APPROVE.value.lower():
            reasons.append("Approved by analyst - incident created")
        elif h_dec == HumanDecision.MORE_INFO.value.lower():
            reasons.append("Analyst requested more information but investigation closed")
            if human_feedback:
                reasons.append(f"Analyst feedback: {human_feedback}")

    # 3. Check reasoning LLM verdict
    elif verdict:
        v_dec = verdict.get("decision")
        verdict_decision = str(getattr(v_dec, "value", v_dec or "")).lower()
        sop_v = verdict.get("sop_verdict")
        if sop_v:
            reasons.append(f"SOP Verdict: {sop_v}")

        if "close" in verdict_decision:
            reasons.append("Closed by AI verdict - likely false positive")
            if verdict.get("recommendation"):
                reasons.append(f"AI recommendation: {verdict['recommendation'][:200]}")
        elif "escalate" in verdict_decision:
            reasons.append("Escalation process completed")
        elif "needs_more_info" in verdict_decision:
            reasons.append("Validation required - escalated for confirmation")

    # 4. Check supervisor decision
    elif supervisor_decision:
        action = str(supervisor_decision.get("next_action") or "").upper()
        if action == "CLOSE":
            reasons.append("Closed by supervisor - insufficient evidence of threat")
            confidence = float(supervisor_decision.get("tp_confidence", 0.0) or 0.0)
            reasons.append(f"True positive confidence: {confidence:.0%}")
            if supervisor_decision.get("confidence_reasoning"):
                reasons.append(f"Reasoning: {supervisor_decision['confidence_reasoning'][:200]}")

    # 5. Default fallback
    if not reasons:
        reasons.append("Investigation completed - no action required")

    return " | ".join(reasons)
