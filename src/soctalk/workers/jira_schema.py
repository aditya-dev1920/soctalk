"""Lightweight Jira payload validator and normalizer used by jira_worker_node.

Provides schema validation, field aliasing, and resilient normalization to
guarantee reliability of LLM-produced triage payloads before dispatching to Jira.
"""

from __future__ import annotations

import re
from typing import Any

# Base required fields
REQUIRED_KEYS = [
    "summary",
    "threat_title",
    "threat_description",
    "impact_for_you",
    "remediation_steps",
    "project",
    "issue_type",
]

# Supported field aliases for LLM outputs
FIELD_ALIASES = {
    "severity": "customfield_10044",
    "analyst_verdict_id": "customfield_10220",
    "analyst_verdict": "customfield_10220",
    "impact": "impact_for_you",
    "remediation": "remediation_steps",
}


def _is_string(v: Any) -> bool:
    return isinstance(v, str) and bool(v.strip())


def _ensure_list_of_strings(v: Any) -> list[str]:
    """Coerce string, list, or empty inputs into a clean list of string items."""
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if x is not None and str(x).strip()]
    if isinstance(v, str):
        lines = [re.sub(r"^[\*\-\d\.]+\s*", "", ln).strip() for ln in v.splitlines() if ln.strip()]
        if len(lines) > 1:
            return lines
        parts = [p.strip() for p in v.split(",") if p.strip()]
        return parts if parts else [v.strip()]
    return [str(v).strip()]


def normalize_jira_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize and coerce payload types, resolving common field aliases."""
    if not isinstance(payload, dict):
        return {}

    out = dict(payload)

    # 1. Resolve field aliases (e.g., severity -> customfield_10044)
    for alias, target in FIELD_ALIASES.items():
        if alias in out and target not in out:
            out[target] = out[alias]

    # 2. String field coercion
    string_keys = (
        "summary",
        "threat_title",
        "threat_description",
        "impact_for_you",
        "project",
        "issue_type",
    )
    for k in string_keys:
        val = out.get(k)
        out[k] = str(val).strip() if val is not None else ""

    # 3. Default fallback values
    if not out.get("project"):
        out["project"] = "SEC"
    if not out.get("issue_type"):
        out["issue_type"] = "Incident"

    # 4. Normalize remediation steps
    out["remediation_steps"] = _ensure_list_of_strings(out.get("remediation_steps"))

    # 5. Coerce custom field select IDs to integers or strings
    for cf in ("customfield_10044", "customfield_10220"):
        v = out.get(cf)
        if isinstance(v, dict) and "id" in v:
            v = v["id"]
        if isinstance(v, str) and v.isdigit():
            out[cf] = int(v)
        elif isinstance(v, int):
            out[cf] = v

    return out


def validate_jira_payload(payload: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate presence and core types of required Jira keys."""
    errors: list[str] = []
    if not isinstance(payload, dict):
        return False, ["payload must be a dict"]

    # Check required core keys
    for k in REQUIRED_KEYS:
        if k not in payload or payload[k] is None:
            errors.append(f"missing required key: {k}")

    # Check custom fields (accept either raw custom field IDs or aliases)
    has_severity = "customfield_10044" in payload or "severity" in payload
    if not has_severity:
        errors.append("missing required severity field (customfield_10044 or severity)")

    has_verdict = "customfield_10220" in payload or "analyst_verdict_id" in payload or "analyst_verdict" in payload
    if not has_verdict:
        errors.append("missing required analyst verdict field (customfield_10220 or analyst_verdict_id)")

    # Type checks
    for key in ("summary", "threat_title", "threat_description", "impact_for_you"):
        if key in payload and not isinstance(payload[key], str):
            errors.append(f"{key} must be a string")

    if "remediation_steps" in payload:
        rem = payload["remediation_steps"]
        if not isinstance(rem, (list, str)):
            errors.append("remediation_steps must be a list or a string")

    return len(errors) == 0, errors


def strict_validate_jira_payload(
    payload: dict[str, Any], template: dict[str, Any]
) -> tuple[bool, list[str]]:
    """Perform SOP-strict validation enforcing regex rules and markdown structure."""
    errors: list[str] = []
    is_basic, basic_errors = validate_jira_payload(payload)
    if not is_basic:
        errors.extend(basic_errors)

    # 1. Summary regex check
    summary_regex = template.get("summary_regex")
    summary = str(payload.get("summary", "")).strip()
    if summary_regex:
        try:
            if not re.match(summary_regex, summary):
                errors.append(f"summary does not match required pattern: {summary_regex}")
        except re.error:
            errors.append("invalid summary regex configured in template")

    # 2. Threat title matching
    threat_title = str(payload.get("threat_title", "")).strip()
    if threat_title != summary:
        errors.append("threat_title must equal summary exactly")

    # 3. Resilient Heading Checks (handles ##, ###, ####, and bold markers)
    td = payload.get("threat_description") or ""
    td_lower = td.lower()

    has_overview = bool(re.search(r"(#{1,4}|\*\*)\s*threat overview", td_lower))
    has_details = bool(re.search(r"(#{1,4}|\*\*)\s*threat details", td_lower))

    if not has_overview or not has_details:
        errors.append("threat_description must include 'Threat Overview' and 'Threat Details' section headers")

    # 4. Threat Overview Field Verification
    required_overview = template.get("required_threat_overview_fields", [])
    if required_overview:
        found_overview = [f for f in required_overview if f.lower() in td_lower]
        if not found_overview:
            errors.append(
                f"threat_description must include at least one overview field from: {', '.join(required_overview)}"
            )

    # 5. Threat Details Field Verification
    required_details = template.get("required_threat_details_fields", [])
    if required_details:
        found_details = [f for f in required_details if f.lower() in td_lower]
        if not found_details:
            errors.append(
                f"threat_description must include at least one details field from: {', '.join(required_details)}"
            )

    # 6. Analysis and Impact Sections Verification
    impact = (payload.get("impact_for_you") or "").lower()
    for sec in template.get("required_analysis_sections", []):
        if sec.lower() not in impact:
            errors.append(f"impact_for_you missing required section: {sec}")

    return len(errors) == 0, errors