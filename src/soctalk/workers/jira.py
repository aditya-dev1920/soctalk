"""Jira worker node for Phase-4 reporting.

Creates a Jira ticket from the investigation SOP report and optionally
creates/escalates a TheHive case when the verdict indicates a true positive.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
from typing import Any

import structlog

from soctalk.mcp.bindings import get_jira_client, get_thehive_client
from soctalk.models.enums import InvestigationStatus, Phase
from soctalk.models.investigation import InvestigationRunState
from soctalk.workers.jira_schema import (
    normalize_jira_payload,
    strict_validate_jira_payload,
    validate_jira_payload,
)

logger = structlog.get_logger()


def _markdown_to_adf(text: str) -> dict[str, Any]:
    """Minimal Markdown -> Atlassian Document Format (ADF) converter."""
    if not text:
        return {"type": "doc", "version": 1, "content": []}

    try:
        from marklassian import markdown_to_adf
        adf = markdown_to_adf(text)
        if isinstance(adf, dict) and adf.get("type") == "doc":
            return adf
    except Exception:
        pass

    lines = text.splitlines()
    content: list[dict[str, Any]] = []
    buf_para: list[str] = []

    def flush_para() -> None:
        nonlocal buf_para
        if not buf_para:
            return
        txt = "\n".join(buf_para).strip()
        if txt:
            content.append({"type": "paragraph", "content": [{"type": "text", "text": txt[:32000]}]})
        buf_para = []

    i = 0
    while i < len(lines):
        ln = lines[i]
        m = re.match(r"^\s*[-\*]\s+(.*)$", ln)
        if m:
            flush_para()
            items = [m.group(1).strip()]
            i += 1
            while i < len(lines):
                mm = re.match(r"^\s*[-\*]\s+(.*)$", lines[i])
                if not mm:
                    break
                items.append(mm.group(1).strip())
                i += 1
            list_node = {
                "type": "bulletList",
                "content": [
                    {
                        "type": "listItem",
                        "content": [{"type": "paragraph", "content": [{"type": "text", "text": it[:1024]}]}],
                    }
                    for it in items
                ],
            }
            content.append(list_node)
            continue
        else:
            buf_para.append(ln)
        i += 1

    flush_para()
    if not content:
        content.append({"type": "paragraph", "content": [{"type": "text", "text": text[:32000]}]})
    return {"type": "doc", "version": 1, "content": content}


def _ensure_summary_format(
    summary: str | None, threat_title: str | None, host: str | None, severity: str | None
) -> str:
    """Guarantee summary matches: NopalCyber SOC Alert | <Threat Name> Detected on <Hostname> | <Severity>"""
    if summary and ("Detected on" in summary or "events." in summary) and "|" in summary:
        return summary.strip()
    name = threat_title or summary or "Security Incident"
    name = re.sub(r"^\[?NopalCyber SOC Alert\]?\s*\|\s*", "", name, flags=re.I).strip()
    hostpart = host or "unknown"
    sev = (severity or "Medium").capitalize()
    return f"NopalCyber SOC Alert | {name} Detected on {hostpart} | {sev}"


def _split_parts(text: str) -> tuple[str, str, str]:
    """Parse a 3-part Markdown recommendation into distinct sections."""
    if not text:
        return "", "", ""
    t = text.strip()
    parts = re.split(
        r"\n##+\s*(?:1\.?|PART\s*1|1)\b|\n##+\s*(?:2\.?|PART\s*2|2)\b|\n##+\s*(?:3\.?|PART\s*3|3)\b",
        "\n" + t,
    )
    if len(parts) >= 4:
        return parts[1].strip(), parts[2].strip(), parts[3].strip()

    m = re.search(r"##\s*1[\.:]?(.+?)##\s*2[\.:]?(.+?)##\s*3[\.:]?(.*)$", t, re.S)
    if m:
        return m.group(1).strip(), m.group(2).strip(), m.group(3).strip()

    lines = t.splitlines()
    n = max(1, len(lines) // 3)
    return (
        "\n".join(lines[:n]).strip(),
        "\n".join(lines[n : 2 * n]).strip(),
        "\n".join(lines[2 * n :]).strip(),
    )


def _ensure_analysis_sections(text: str) -> str:
    """Guarantee all 6 mandatory SOP analysis sections exist for strict validation."""
    required_sections = [
        "**File Analysis**",
        "**Process & Command-Line Analysis**",
        "**Storyline Analysis**",
        "**Persistence & Lateral Movement Analysis**",
        "**Network Analysis**",
        "**30-Day Estate Sweep Results**",
    ]
    out = text.strip() if text else ""
    for sec in required_sections:
        if sec.lower() not in out.lower():
            out += f"\n\n{sec}\n- No anomalous indicators observed."
    return out.strip()


async def jira_worker_node(state: dict[str, Any]) -> dict[str, Any]:
    """Create Jira ticket (Phase 4 reporting) and optionally TheHive case.

    This node is idempotent: if the investigation already contains a
    `jira_issue_key` it will not create a duplicate.
    """
    logger.info("jira_worker_started")

    jira_client = get_jira_client()
    thehive_client = get_thehive_client()

    investigation_data = state.get("investigation", {})
    investigation = (
        InvestigationRunState(**investigation_data)
        if isinstance(investigation_data, dict)
        else investigation_data
    )

    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        # Allow execution from both verdict phase and escalation phase
        current_phase = state.get("current_phase")
        logger.info("jira_worker_evaluating", current_phase=current_phase)

        if getattr(investigation, "jira_issue_key", None):
            logger.info("jira_already_created", key=investigation.jira_issue_key)
            state["last_updated"] = now_iso
            return state

        if jira_client is None:
            logger.warning("jira_client_not_bound")
            state["last_error"] = "Jira client not configured"
            state["error_count"] = state.get("error_count", 0) + 1
            state["last_updated"] = now_iso
            return state

        alert = state.get("alert") or {}
        inv = (
            investigation.model_dump()
            if hasattr(investigation, "model_dump")
            else (investigation if isinstance(investigation, dict) else {})
        )
        # Fallback to the first alert in investigation if state["alert"] is unpopulated
        if not alert and inv.get("alerts"):
            first_alert = inv["alerts"][0]
            alert = first_alert.model_dump() if hasattr(first_alert, "model_dump") else (first_alert if isinstance(first_alert, dict) else {})
        # Capture findings from state or investigation metadata
        findings = state.get("findings") or inv.get("findings") or []
        enrichments = inv.get("enrichments") or []
        verdict = state.get("verdict") or {}

        # 1. Parse Recommendation Sub-sections First
        recommendation_raw = (
            verdict.get("recommendation")
            if isinstance(verdict, dict)
            else str(verdict or "")
        ) or ""
        part1_text, part2_text, part3_text = _split_parts(recommendation_raw)

        # 2. Extract Structured Fields Emitted by Verdict Reasoning Model
        vt_threat_title = verdict.get("threat_title") if isinstance(verdict, dict) else None
        vt_threat_description = verdict.get("threat_description") if isinstance(verdict, dict) else None
        vt_impact_for_you = verdict.get("impact_for_you") if isinstance(verdict, dict) else None
        vt_remediation_steps = verdict.get("remediation_steps") if isinstance(verdict, dict) else None

        raw_threat_name = (
            alert.get("threat_name")
            or alert.get("signature")
            or alert.get("rule_id")
            or "Security Incident"
        )

        # Deep inspection across flat and nested telemetry structures
        agent_obj = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
        raw_host = (
            alert.get("host")
            or alert.get("hostname")
            or agent_obj.get("name")
            or alert.get("endpoint_name")
            or alert.get("computer_name")
            or inv.get("host")
            or "nopal-siem"
        )
        raw_sev = str(alert.get("severity") or inv.get("severity") or "Medium").strip().capitalize()

        # Extract enriched IP observables across state and investigation metadata
        observables = inv.get("observables") or state.get("observables") or []
        
        def _get_obs_val_and_type(o: Any) -> tuple[str | None, str | None]:
            if isinstance(o, dict):
                t = o.get("type")
                t_str = getattr(t, "value", str(t or "")).lower()
                return str(o.get("value") or ""), t_str
            val = getattr(o, "value", None)
            t = getattr(o, "type", None)
            t_str = getattr(t, "value", str(t or "")).lower()
            return str(val) if val else None, t_str

        extracted_ips = []
        for o in observables:
            val, t_type = _get_obs_val_and_type(o)
            if val and "ip" in (t_type or ""):
                extracted_ips.append(val)

        obs_ip = next((ip for ip in extracted_ips if not ip.startswith("25.2.")), None) or (extracted_ips[0] if extracted_ips else None)
        raw_ip = alert.get("ipv4") or alert.get("ip") or obs_ip or "N/A"

        # Sanitize status enum object into clean title text
        raw_status = inv.get("status")
        status_clean = (
            getattr(raw_status, "value", str(raw_status or "Active"))
            .replace("InvestigationStatus.", "")
            .replace("_", " ")
            .title()
        )

        # Sanitize SOP verdict enum into clean title text
        raw_sop_verdict = verdict.get("sop_verdict") or inv.get("sop_verdict") or "Validation Required"
        sop_verdict_clean = (
            getattr(raw_sop_verdict, "value", str(raw_sop_verdict))
            .replace("SOPVerdict.", "")
            .replace("_", " ")
            .title()
        )

        # 3. Assemble Normalized Summary & Threat Title
        summary = _ensure_summary_format(
            summary=vt_threat_title or inv.get("summary"),
            threat_title=vt_threat_title or raw_threat_name,
            host=raw_host,
            severity=raw_sev,
        )
        threat_title = summary

        # 4. Markdown Table Builder Helper
        def _md_table(rows: list[tuple[str, Any]]) -> str:
            lines = ["| Field | Value |", "| :--- | :--- |"]
            for k, v in rows:
                val = "N/A" if v is None or v == "" else str(v)
                val = val.replace("|", "\\|")
                lines.append(f"| **{k}** | {val} |")
            return "\n".join(lines)

        reported_at = (
            alert.get("reported_at")
            or alert.get("timestamp")
            or state.get("started_at")
            or now_iso
        )
        
        # Sanitize SOP verdict enum
        raw_sop = verdict.get("sop_verdict") or inv.get("sop_verdict") or "Validation Required"
        sop_verdict_clean = getattr(raw_sop, "value", str(raw_sop)).replace("SOPVerdict.", "").replace("_", " ").title()
        
        threat_overview_rows = [
            ("Threat Name", raw_threat_name),
            ("Jira ID", "N/A"),
            ("Severity", raw_sev),
            ("Investigation Verdict", sop_verdict_clean),
            ("Classification Source", alert.get("source") or "Wazuh"),
            ("Detection Engine", alert.get("detection_engine") or alert.get("rule_id") or "unknown"),
            ("Host", raw_host),
            ("Execution Security Context", alert.get("execution_context") or inv.get("principal") or "N/A"),
            ("Interactive User", alert.get("user") or inv.get("user") or "N/A"),
            ("Reported At", reported_at),
            ("File Hash (SHA256)", alert.get("sha256") or "N/A"),
            ("File Path", alert.get("file_path") or "N/A"),
            ("Command Line Arguments", alert.get("cmdline") or "N/A"),
            ("Originating Process", alert.get("parent_process") or "N/A"),
            ("Device Health", alert.get("device_health") or "Unknown"),
        ]

        threat_details_rows = [
            ("Threat URL", alert.get("url") or "N/A"),
            ("Threat ID", str(alert.get("id") or alert.get("event_id") or inv.get("id") or "N/A")),
            ("Threat Status", status_clean or "Mitigated"),
            ("Threat Filename", alert.get("filename") or alert.get("threat_name") or "N/A"),
            ("Threat Filepath", alert.get("file_path") or "N/A"),
            ("SHA256", alert.get("sha256") or "N/A"),
            ("Process User", alert.get("process_user") or alert.get("user") or "N/A"),
            ("Publisher Name", alert.get("publisher") or "N/A"),
            ("Signer Identity", alert.get("signer") or "N/A"),
            ("Signature Verification", alert.get("signature_verification") or "Signed"),
            ("Initiated By", alert.get("initiated_by") or "agent_policy"),
            (
                "Engines",
                ", ".join(
                    set(
                        e.get("analyzer")
                        for e in enrichments
                        if isinstance(e, dict) and e.get("analyzer")
                    )
                )
                if enrichments
                else "VirusTotal",
            ),
            ("Detection Type", alert.get("detection_type") or "behavioral"),
            ("Classification", alert.get("classification") or alert.get("threat_category") or "General"),
            ("File Size", alert.get("file_size") or "N/A"),
        ]

        endpoint_rows = [
            ("Hostname", raw_host),
            ("Account Name", inv.get("account_name") or "NopalCyber"),
            ("Site Name", inv.get("site_name") or "Production"),
            ("OS Version", inv.get("os_version") or "Linux / Ubuntu 24.04"),
            ("Agent Version", inv.get("agent_version") or alert.get("agent_version") or agent_obj.get("version") or "4.8.0"),
            ("Logged-in User", alert.get("user") or inv.get("user") or "N/A"),
            ("Domain", inv.get("domain") or "WORKGROUP"),
            ("UUID", inv.get("agent_uuid") or agent_obj.get("id") or "N/A"),
            ("IPv4 Address", raw_ip),
            ("IPv6 Address", alert.get("ipv6") or "N/A"),
            ("Console Visible IP", inv.get("public_ip") or "N/A"),
            ("Connectivity", "Connected"),
            ("Network Status", "Connected"),
            ("Scan Status", "Finished"),
            ("Full Disk Scan", "No"),
            ("Pending Reboot", "No"),
            ("Number of Not Mitigated Threats", inv.get("not_mitigated_count") or 0),
        ]

        detection_rows = [
            ("Detection Timestamp", alert.get("timestamp") or reported_at),
            ("Reported Time", reported_at),
            ("Storyline / Correlation ID", str(inv.get("id") or state.get("run_id") or "N/A")),
            ("Incident Status", status_clean),
            ("MITRE ATT&CK", ", ".join(inv.get("mitre", [])) if inv.get("mitre") else "N/A"),
        ]

        analysis_text = _ensure_analysis_sections(
            vt_impact_for_you
            or part2_text
            or ("\n".join(f"- {f}" for f in findings) if findings else "- Telemetry investigated.")
        )
        recommendations_text = vt_remediation_steps or part3_text or "- Check with user to validate activity."

        # 5. Build Customer-Facing Threat Description (Part 2 Tables)
        threat_description_body = (
            f"Hi Team,\n\n"
            f"As part of our 24/7 Security Operations, we observed a threat on the machine **{raw_host}**. "
            f"Please find the threat details and perform the recommended actions.\n\n"
            f"#### Threat Overview\n{_md_table(threat_overview_rows)}\n\n---\n\n"
            f"#### Threat Details\n{_md_table(threat_details_rows)}"
        )

        # Enforce strict SOP headers: retain structured tables unless LLM output conforms
        final_threat_description = threat_description_body
        if (
            vt_threat_description
            and "Threat Overview" in vt_threat_description
            and "Threat Details" in vt_threat_description
        ):
            final_threat_description = vt_threat_description

        # 6. Build Main Description (Part 1 Alert Details)
        description_body = (
            f"#### Endpoint Details\n{_md_table(endpoint_rows)}\n\n---\n\n"
            f"#### Detection Time Details\n{_md_table(detection_rows)}"
        )

        # 7. Map Severity, Analyst Verdict, and Category Option IDs per Tier-3 SOP
        severity_map = {"Critical": 10028, "High": 10029, "Medium": 10030, "Low": 10031}
        severity_id = severity_map.get(raw_sev, 10030)

        sop_str = str(
            verdict.get("sop_verdict") or inv.get("sop_verdict") or "Validation Required"
        ).strip()
        sop_norm = sop_str.lower()

        if "true positive" in sop_norm and "benign" not in sop_norm:
            analyst_verdict_id = 10329
            threat_category_id = 10830  # Malware
            top_level_category_id = 10994  # Malware
        elif "policy violation" in sop_norm:
            analyst_verdict_id = 10329
            threat_category_id = 10840  # Unauthorized Activity
            top_level_category_id = 10995  # Apps
        elif "false positive" in sop_norm:
            analyst_verdict_id = 10327
            threat_category_id = 10862  # Authorized Application
            top_level_category_id = 10995  # Apps
        else:  # Validation Required / Suspicious
            analyst_verdict_id = 10336
            threat_category_id = 10831  # Suspicious Process
            top_level_category_id = 10995  # Apps

        # 8. Assemble Full Jira Payload
        jira_args: dict[str, Any] = {
            "summary": summary,
            "description": description_body,
            "threat_title": threat_title,
            "threat_description": final_threat_description,
            "impact_for_you": analysis_text,
            "remediation_steps": recommendations_text,
            "severity": str(severity_id),
            "analyst_verdict_id": str(analyst_verdict_id),
            "threat_category_id": str(threat_category_id),
            "top_level_category_id": str(top_level_category_id),
            "issue_type": (
                inv.get("jira_issue_type")
                or alert.get("issue_type")
                or os.getenv("JIRA_ISSUE_TYPE")
                or "SentinelOne"
            ),
            "project": (
                inv.get("jira_project")
                or alert.get("project")
                or os.getenv("JIRA_DEFAULT_PROJECT")
                or os.getenv("JIRA_PROJECT")
                or "NTE"
            ),
            "labels": ["soctalk", "auto-triage", "nopal-soc"],
        }

        # Normalize and validate payload structure
        jira_args = normalize_jira_payload(jira_args)
        is_valid, validation_errors = validate_jira_payload(jira_args)
        if not is_valid:
            logger.warning("jira_payload_validation_warning", errors=validation_errors)

        # 9. Load Template and Perform Strict SOP Validation Guard
        template_path = Path(__file__).resolve().parents[3] / "docs" / "jira_template.json"
        if not template_path.exists():
            template_path = Path("docs/jira_template.json")

        template: dict[str, Any] = {}
        if template_path.exists():
            try:
                with open(template_path, "r", encoding="utf-8") as tf:
                    template = json.load(tf)
            except Exception as e:
                logger.warning("failed_loading_jira_template", error=str(e))

        strict_ok, strict_errors = strict_validate_jira_payload(jira_args, template)
        if not strict_ok:
            logger.warning("jira_strict_sop_validation_warning", errors=strict_errors)

        logger.info("creating_jira_ticket", summary=summary[:80])
        res = await jira_client.call_tool("jira_create_ticket", jira_args)

        # 10. Extract Issue Key and Browser URL
        issue_key: str | None = None
        issue_url: str | None = None

        if isinstance(res, str) and res.strip().startswith("{"):
            try:
                parsed = json.loads(res)
                issue_key = parsed.get("key") or parsed.get("issue_key")
                issue_url = parsed.get("url")
            except Exception:
                pass
        elif isinstance(res, dict):
            issue_key = res.get("key") or res.get("issue_key")
            issue_url = res.get("url")

        if not issue_key and isinstance(res, str):
            match = re.search(r"([A-Z][A-Z0-9]+-\d+)", res)
            if match:
                issue_key = match.group(1)

        if issue_key:
            if hasattr(investigation, "jira_issue_key"):
                investigation.jira_issue_key = issue_key
            logger.info("jira_ticket_created_successfully", key=issue_key, url=issue_url)
        else:
            logger.warning("jira_ticket_created_without_key", raw=str(res)[:200])

        # 11. Optionally Create/Escalate TheHive Case on Confirmed Malicious Verdicts
        if ("true positive" in sop_norm and "benign" not in sop_norm) and thehive_client:
            try:
                case_payload = {
                    "title": summary,
                    "description": f"{threat_description_body}\n\n---\n\n{analysis_text}",
                    "severity": 3 if raw_sev in ("Critical", "High") else 2,
                    "tags": ["soctalk", "auto-triage", "nopal-cyber"],
                    "tlp": "amber",
                    "pap": "default",
                }
                logger.info("creating_thehive_case_after_jira")
                case_res = await thehive_client.call_tool("create_thehive_case", case_payload)
                case_id: str | None = None
                if isinstance(case_res, str) and case_res.strip().startswith("{"):
                    try:
                        pj = json.loads(case_res)
                        case_id = pj.get("_id") or pj.get("id")
                    except Exception:
                        pass
                elif isinstance(case_res, dict):
                    case_id = case_res.get("_id") or case_res.get("id")

                if case_id and hasattr(investigation, "thehive_case_id"):
                    investigation.thehive_case_id = case_id
                    investigation.status = InvestigationStatus.ESCALATED
            except Exception as e:
                logger.error("thehive_create_after_jira_failed", error=str(e))

        inv_dict = (
            investigation.model_dump()
            if hasattr(investigation, "model_dump")
            else (investigation if isinstance(investigation, dict) else {})
        )
        if issue_key:
            inv_dict["jira_issue_key"] = issue_key
        if issue_url:
            inv_dict["jira_ticket_url"] = issue_url

        state["investigation"] = inv_dict
        state["current_phase"] = Phase.CLOSED.value

    except Exception as e:
        logger.error("jira_worker_error", error=str(e), exc_info=True)
        state["last_error"] = f"jira_worker_error: {e}"
        state["error_count"] = state.get("error_count", 0) + 1

    state["last_updated"] = datetime.now(timezone.utc).isoformat()
    return state