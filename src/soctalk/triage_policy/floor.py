"""The non-overridable safety floor on the auto-close path (issue #43).

Auto-close happens in two planes, and the floor must veto in both:

- the runs-worker maps a graph terminal state to a ``close_fp`` disposition
  (``runs_worker/main.py``) which ``complete_run()`` applies as ``auto_closed_fp`` —
  ``worker_close_vetoes`` below is the pure check for that plane;
- the IR ingest path applies memoized and rules auto-close after correlation
  (``core/ir/triage.py``) — that plane needs the DB (active-incident lookup), so its
  check lives in ``triage.py`` next to the close sites and shares this module's
  reason vocabulary.

The floor is enforced by the executor, is not expressible in a triage policy, and always
applies — a triage policy can only add stricter gates. Without this, a misconfigured or
malicious triage policy becomes a detection-suppression channel.
"""

from __future__ import annotations

from typing import Any

from soctalk.authorization.render import has_malicious_signal, parse_authorization_context
from soctalk.triage_policy.guard import derive_authz_class

VETO_IOC = "ioc_present"
VETO_UNVERIFIED_IOC = "ioc_unverified"
VETO_ACTIVE_INCIDENT = "active_incident"
VETO_AUTHZ_CONTRADICTED = "authorization_contradicted"
VETO_KILL_SWITCH = "auto_close_killed"
VETO_VOLUME_CAP = "close_volume_cap"
VETO_SOP_VERDICT = "sop_verdict_veto"

# Audit actions on the API/IR planes (queried like other ir.* rows).
FLOOR_AUDIT_ACTION = "ir.triage_policy.close_floor_veto"
TRIAGE_POLICY_AUDIT_ACTION = "ir.triage_policy.audit"


def auto_close_killed(policy: dict[str, Any] | None = None) -> bool:
    """The auto-close kill switch (issue #46): install-wide via the
    ``SOCTALK_AUTO_CLOSE_KILL`` env on the API process, or per tenant via the
    ``auto_close_kill`` policy row (a runtime flip, no rollout). Either being on
    kills EVERY automatic close — rules band, memoized close, worker close_fp,
    triage policy operational disposition — flipping them to promote/escalate. The
    policy flag must be a real boolean True (a stringly "false" is not True)."""
    import os

    if os.getenv("SOCTALK_AUTO_CLOSE_KILL", "").lower() in ("1", "true", "yes"):
        return True
    return bool(policy) and policy.get("auto_close_kill") is True


def worker_close_vetoes(final_state: dict[str, Any]) -> list[str]:
    """Floor reasons that forbid a ``close_fp`` disposition for this graph run.

    Pure over the graph's terminal state. Vetoes include:
    - IOC: a malicious enrichment verdict or a MISP IOC match.
    - unverified IOC: a close with NO verdict while IOC observables were never enriched.
    - contradicted authorization: records present but fail to cover.
    - SOP Verdict: explicit SOP classification as True Positive – Malicious or Validation Required.
    """
    vetoes: list[str] = []
    investigation = final_state.get("investigation") or {}
    if has_malicious_signal(investigation):
        vetoes.append(VETO_IOC)
    
    # SOP Verdict Safety Check: Never allow closing on Malicious or Validation Required
    verdict = final_state.get("verdict") or {}
    sop_verdict = str(verdict.get("sop_verdict") or "")
    if sop_verdict in {"True Positive – Malicious", "Validation Required"}:
        vetoes.append(VETO_SOP_VERDICT)

    if not final_state.get("verdict") and _has_unenriched_observables(investigation):
        vetoes.append(VETO_UNVERIFIED_IOC)
    authz_class, _ = derive_authz_class(parse_authorization_context(investigation))
    if authz_class == "contradicted":
        vetoes.append(VETO_AUTHZ_CONTRADICTED)
    correlation = final_state.get("correlation") or {}
    if isinstance(correlation, dict) and correlation.get("active_incident"):
        vetoes.append(VETO_ACTIVE_INCIDENT)
    return vetoes


def _has_unenriched_observables(investigation: dict[str, Any]) -> bool:
    """Any IOC observable on the investigation that no enrichment ever covered."""
    observables = investigation.get("observables") or []
    if not observables:
        return False
    enriched = {
        (e.get("observable") or {}).get("value")
        for e in investigation.get("enrichments") or []
        if isinstance(e, dict)
    }
    return any(
        isinstance(o, dict) and o.get("value") and o["value"] not in enriched
        for o in observables
    )


def apply_worker_floor(
    final_state: dict[str, Any], disposition: str | None
) -> tuple[str | None, list[str]]:
    """Terminal veto for the runs-worker plane: a ``close_fp`` with floor vetoes
    becomes ``escalate`` (never silently dropped — an analyst sees it). Any other
    disposition passes through untouched."""
    if disposition != "close_fp":
        return disposition, []
    vetoes = worker_close_vetoes(final_state)
    if vetoes:
        return "escalate", vetoes
    return disposition, []
