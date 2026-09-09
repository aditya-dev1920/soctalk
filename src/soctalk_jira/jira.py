"""SocTalk MCP Server for Atlassian Jira.

Provides production-grade Jira Cloud & Data Center issue management for
LangGraph agent triage workflows, handling native ADF formatting, custom fields,
JQL searching, comments, issue inspection, transitions, and subtask creation with robust fallbacks.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any

import httpx
from dotenv import load_dotenv
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

load_dotenv()

logging.basicConfig(
    level=os.getenv("MCP_TOOL_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s:%(name)s:%(message)s",
)
logger = logging.getLogger("soctalk.mcp.jira")
server = Server("jira")


def _result(data: Any) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


def _sanitize_text(text: Any, default: str = "N/A") -> str:
    """Ensure text is a non-empty string to prevent ADF schema validation rejections."""
    s = str(text or "").strip()
    return s if s else default


def _coerce_to_str(val: Any) -> str:
    """Coerce string, list of strings, or dictionaries into a clean string representation."""
    if val is None:
        return ""
    if isinstance(val, list):
        return "\n".join(f"* {str(x).strip()}" for x in val if str(x).strip())
    return str(val).strip()


def _parse_inline_formatting(text: str) -> list[dict[str, Any]]:
    """Parse inline bold (**text**) and code (`code`) tokens into ADF text nodes."""
    tokens = re.split(r"(\*\*.*?\*\*|`.*?`)", text)
    nodes: list[dict[str, Any]] = []
    for token in tokens:
        if not token:
            continue
        if token.startswith("**") and token.endswith("**") and len(token) >= 4:
            nodes.append({"type": "text", "text": token[2:-2], "marks": [{"type": "strong"}]})
        elif token.startswith("`") and token.endswith("`") and len(token) >= 2:
            nodes.append({"type": "text", "text": token[1:-1], "marks": [{"type": "code"}]})
        else:
            nodes.append({"type": "text", "text": token})
    return nodes or [{"type": "text", "text": text}]


def _text_to_adf(text: str | None) -> dict[str, Any]:
    """Convert Markdown or raw text into valid Atlassian Document Format (ADF)."""
    raw = (text or "").strip()
    if not raw:
        return {
            "version": 1,
            "type": "doc",
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": "No details provided."}],
                }
            ],
        }

    # 1. Attempt native marklassian conversion if installed
    try:
        from marklassian import markdown_to_adf
        adf = markdown_to_adf(raw)
        if isinstance(adf, dict) and adf.get("type") == "doc":
            return adf
    except ImportError:
        pass
    except Exception as e:
        logger.debug("marklassian conversion bypassed: %s", e)

    # 2. Native Markdown-to-ADF Parser
    content: list[dict[str, Any]] = []
    lines = raw.split("\n")
    i = 0

    while i < len(lines):
        line = lines[i]
        trimmed = line.strip()

        if not trimmed:
            i += 1
            continue

        # Headings (# H1, ## H2, ### H3, #### H4)
        heading_match = re.match(r"^(#{1,6})\s+(.*)$", trimmed)
        if heading_match:
            level = len(heading_match.group(1))
            heading_text = _sanitize_text(heading_match.group(2), "Section")
            content.append({
                "type": "heading",
                "attrs": {"level": min(level, 4)},
                "content": [{"type": "text", "text": heading_text[:512]}],
            })
            i += 1
            continue

        # Code blocks (```lang ... ```)
        if trimmed.startswith("```"):
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            i += 1  # Skip closing ```
            code_text = _sanitize_text("\n".join(code_lines), "Empty Code Block")
            content.append({
                "type": "codeBlock",
                "content": [{"type": "text", "text": code_text[:16000]}],
            })
            continue

        # Bullet Lists (* item, - item)
        if trimmed.startswith(("* ", "- ")):
            list_items = []
            while i < len(lines) and lines[i].strip().startswith(("* ", "- ")):
                item_text = _sanitize_text(re.sub(r"^[\*\-]\s+", "", lines[i].strip()), "Item")
                list_items.append({
                    "type": "listItem",
                    "content": [{
                        "type": "paragraph",
                        "content": _parse_inline_formatting(item_text[:1024]),
                    }],
                })
                i += 1
            if list_items:
                content.append({"type": "bulletList", "content": list_items})
            continue

        # Standard Paragraphs
        paragraph_lines = [trimmed]
        i += 1
        while i < len(lines) and lines[i].strip() and not lines[i].strip().startswith(("#", "```", "* ", "- ")):
            paragraph_lines.append(lines[i].strip())
            i += 1

        p_text = _sanitize_text(" ".join(paragraph_lines), "Details")
        content.append({
            "type": "paragraph",
            "content": _parse_inline_formatting(p_text[:32000]),
        })

    if not content:
        content.append({
            "type": "paragraph",
            "content": [{"type": "text", "text": _sanitize_text(raw, "Report Content")[:32000]}],
        })

    return {"version": 1, "type": "doc", "content": content}


def _get_credentials() -> dict[str, Any]:
    """Dynamically resolve Jira credentials from environment or integration configs."""
    url = (os.getenv("JIRA_URL") or os.getenv("JIRA_BASE_URL") or "").rstrip("/")
    email = os.getenv("JIRA_EMAIL") or os.getenv("JIRA_USERNAME") or ""
    token = os.getenv("JIRA_API_TOKEN") or os.getenv("JIRA_PASSWORD") or os.getenv("JIRA_TOKEN") or ""
    bearer_token = os.getenv("JIRA_BEARER_TOKEN") or ""
    default_project = os.getenv("JIRA_DEFAULT_PROJECT") or os.getenv("JIRA_PROJECT_KEY") or "SEC"
    verify_ssl = os.getenv("JIRA_VERIFY_SSL", "true").strip().lower() in {"1", "true", "yes"}

    # Default custom field mapping for NopalCyber MDR Schema
    default_custom_fields = {
        "threat_title": "customfield_10299",
        "threat_description": "customfield_10402",
        "impact": "customfield_10404",
        "remediation": "customfield_10403",
        "severity": "customfield_10044",
        "analyst_verdict": "customfield_10220",
        "threat_category": "customfield_10303",
        "top_level_category": "customfield_10534",
        "request_type": "customfield_10010",
        "assigned_group": "customfield_10115",
    }

    custom_fields_raw = os.getenv("JIRA_CUSTOM_FIELDS_JSON", "")
    if custom_fields_raw:
        try:
            custom_fields = json.loads(custom_fields_raw)
        except Exception:
            custom_fields = default_custom_fields
    else:
        custom_fields = default_custom_fields

    return {
        "url": url,
        "email": email,
        "token": token,
        "bearer_token": bearer_token,
        "default_project": default_project,
        "verify_ssl": verify_ssl,
        "custom_fields": custom_fields,
    }


def _get_auth_headers(creds: dict[str, Any]) -> tuple[Any, dict[str, str]]:
    """Build authentication headers for Cloud (Basic) or Server/DC (Bearer)."""
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "SocTalk-Jira-MCP/0.3.5",
    }
    if creds.get("bearer_token"):
        headers["Authorization"] = f"Bearer {creds['bearer_token']}"
        return None, headers
    return (creds.get("email"), creds.get("token")), headers


def _map_priority(severity_input: str | None) -> str:
    """Normalize severity ratings to standard Jira priority names."""
    if not severity_input:
        return "Medium"
    s = str(severity_input).strip().lower()
    if s in {"critical", "12", "13", "14", "15", "10028", "highest"}:
        return "Highest"
    if s in {"high", "8", "9", "10", "11", "10029"}:
        return "High"
    if s in {"medium", "4", "5", "6", "7", "10030"}:
        return "Medium"
    if s in {"low", "1", "2", "3", "10031", "lowest"}:
        return "Low"
    return "Medium"


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="jira_create_ticket",
            description=(
                "Create a Jira security incident ticket matching the NopalCyber MDR format. "
                "Generates structured Markdown tables for Threat, Endpoint, and Detection details, "
                "with deep-dive Analysis and SOC Recommendations."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Issue summary in format: 'NopalCyber SOC Alert | <Threat Name> Detected on <Hostname> | <Severity>'."
                    },
                    "description": {
                        "type": "string",
                        "description": "Main report description body containing Threat, Endpoint, and Detection tables."
                    },
                    "threat_title": {
                        "type": "string",
                        "description": "Threat title header (e.g., 'NopalCyber SOC Alert | UMP.v1.3.zip Detected on Dell | Medium')."
                    },
                    "threat_description": {
                        "type": "string",
                        "description": "Threat Description section (customfield_10402)."
                    },
                    "impact_for_you": {
                        "type": ["string", "array"],
                        "description": "Analysis and Impact section covering File, Process, Storyline, Persistence, and Network analysis (customfield_10404)."
                    },
                    "remediation_steps": {
                        "type": ["string", "array"],
                        "description": "SOC Recommendations section with containment, eradication, and policy steps (customfield_10403)."
                    },
                    "severity": {
                        "type": "string",
                        "description": "Severity option ID (10028=Critical, 10029=High, 10030=Medium, 10031=Low) or name."
                    },
                    "issue_type": {
                        "type": "string",
                        "default": "Incident",
                        "description": "Jira Issue Type (e.g., Incident, Task, SentinelOne)."
                    },
                    "project": {
                        "type": "string",
                        "description": "Target Jira project key. Defaults to JIRA_DEFAULT_PROJECT."
                    },
                    "analyst_verdict_id": {
                        "type": "string",
                        "description": "Analyst Verdict option ID (e.g., 10765 for Validation Required, 10327 for True Positive)."
                    },
                    "threat_category_id": {
                        "type": "string",
                        "description": "Threat Category option ID (customfield_10303)."
                    },
                    "top_level_category_id": {
                        "type": "string",
                        "description": "Top Level Category option ID (customfield_10534)."
                    },
                    "labels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional label tags."
                    }
                },
                "required": ["summary", "description"]
            }
        ),
        types.Tool(
            name="jira_get_issue",
            description="Fetch full details, status, priority, resolution, and comments for an existing Jira issue key.",
            inputSchema={
                "type": "object",
                "properties": {
                    "issue_key": {
                        "type": "string",
                        "description": "Jira issue key (e.g., NTE-140401)."
                    }
                },
                "required": ["issue_key"]
            }
        ),
        types.Tool(
            name="jira_search",
            description="Search Jira issues using JQL with deduplication checks and pagination support.",
            inputSchema={
                "type": "object",
                "properties": {
                    "jql": {
                        "type": "string",
                        "description": "JQL query string (e.g., 'project = NTE AND status != Closed AND text ~ \"UMP.v1.3.zip\"')."
                    },
                    "max_results": {
                        "type": "integer",
                        "default": 10,
                        "description": "Maximum number of issues to return (1-50)."
                    }
                },
                "required": ["jql"]
            }
        ),
        types.Tool(
            name="jira_add_comment",
            description="Append an investigation update, threat intelligence report, or timeline note to a Jira issue.",
            inputSchema={
                "type": "object",
                "properties": {
                    "issue_key": {
                        "type": "string",
                        "description": "Jira issue key (e.g., NTE-140401)."
                    },
                    "comment": {
                        "type": "string",
                        "description": "Comment body in Markdown format."
                    }
                },
                "required": ["issue_key", "comment"]
            }
        ),
        types.Tool(
            name="jira_transition_issue",
            description="Transition a Jira issue to a new status (e.g., 'In Progress', 'Resolved', 'Closed').",
            inputSchema={
                "type": "object",
                "properties": {
                    "issue_key": {
                        "type": "string",
                        "description": "Jira issue key (e.g., NTE-140401)."
                    },
                    "transition_name": {
                        "type": "string",
                        "description": "Target transition or status name (e.g., 'In Progress', 'Done', 'Closed')."
                    }
                },
                "required": ["issue_key", "transition_name"]
            }
        ),
        types.Tool(
            name="jira_create_subtask",
            description="Create a subtask under an existing Jira incident for containment, identity lock, or eradication tasks.",
            inputSchema={
                "type": "object",
                "properties": {
                    "parent_issue_key": {
                        "type": "string",
                        "description": "Key of the parent issue (e.g., NTE-140401)."
                    },
                    "summary": {
                        "type": "string",
                        "description": "Short summary of the remediation subtask."
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed instructions for the subtask."
                    },
                    "subtask_issue_type": {
                        "type": "string",
                        "default": "Sub-task",
                        "description": "Subtask issue type name in Jira."
                    }
                },
                "required": ["parent_issue_key", "summary"]
            }
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    creds = _get_credentials()
    if not creds["url"] or (not creds["token"] and not creds["bearer_token"]):
        return _result({
            "success": False,
            "error": "Jira integration not configured. Ensure JIRA_URL and JIRA_API_TOKEN (or JIRA_BEARER_TOKEN) are set.",
        })

    args = arguments or {}
    auth, headers = _get_auth_headers(creds)
    base_url = creds["url"]
    default_project = creds["default_project"]

    async with httpx.AsyncClient(verify=creds["verify_ssl"], timeout=30.0) as client:
        try:
            # -------------------------------------------------------------
            # Tool 1: jira_create_ticket (NopalCyber MDR Template)
            # -------------------------------------------------------------
            if name == "jira_create_ticket":
                summary = _sanitize_text(args.get("summary"), "NopalCyber SOC Alert | Security Incident")[:255]
                desc = _coerce_to_str(args.get("description"))
                threat_title = str(args.get("threat_title") or summary)[:255]
                threat_desc = _coerce_to_str(args.get("threat_description"))
                impact = _coerce_to_str(args.get("impact_for_you"))
                remediation = _coerce_to_str(args.get("remediation_steps"))
                severity_val = args.get("severity") or "10030"
                project_key = _sanitize_text(args.get("project") or default_project, "SEC").upper()
                issue_type = _sanitize_text(args.get("issue_type") or "Incident", "Incident")
                labels = args.get("labels") or ["soctalk", "auto-triage", "nopal-soc"]

                # Composite fallback body if custom fields are not present on screen
                composite_body_parts = [desc]
                if impact:
                    composite_body_parts.append(f"## Analysis and Impact\n{impact}")
                if remediation:
                    composite_body_parts.append(f"## SOC Recommendations\n{remediation}")
                full_description_text = "\n\n---\n\n".join(filter(None, composite_body_parts))

                fields: dict[str, Any] = {
                    "project": {"key": project_key},
                    "summary": summary,
                    "description": _text_to_adf(desc if (impact or remediation) else full_description_text),
                    "issuetype": {"name": issue_type},
                    "priority": {"name": _map_priority(severity_val)},
                    "labels": [re.sub(r"[^\w-]", "", str(lbl))[:255] for lbl in labels if str(lbl).strip()],
                }

                cf = creds.get("custom_fields", {})

                # Text Custom Fields: Single-line uses string; multi-line uses ADF
                if threat_title and cf.get("threat_title"):
                    fields[cf["threat_title"]] = threat_title
                if threat_desc and cf.get("threat_description"):
                    fields[cf["threat_description"]] = _text_to_adf(threat_desc)
                if impact and cf.get("impact"):
                    fields[cf["impact"]] = _text_to_adf(impact)
                if remediation and cf.get("remediation"):
                    fields[cf["remediation"]] = _text_to_adf(remediation)

                # Select Option Custom Fields
                if severity_val and cf.get("severity"):
                    s_val = str(severity_val)
                    fields[cf["severity"]] = {"id": s_val} if s_val.isdigit() else {"value": s_val}

                if args.get("analyst_verdict_id") and cf.get("analyst_verdict"):
                    v_val = str(args["analyst_verdict_id"])
                    fields[cf["analyst_verdict"]] = {"id": v_val} if v_val.isdigit() else {"value": v_val}

                if args.get("threat_category_id") and cf.get("threat_category"):
                    tc_val = str(args["threat_category_id"])
                    fields[cf["threat_category"]] = {"id": tc_val} if tc_val.isdigit() else {"value": tc_val}

                if args.get("top_level_category_id") and cf.get("top_level_category"):
                    tlc_val = str(args["top_level_category_id"])
                    fields[cf["top_level_category"]] = {"id": tlc_val} if tlc_val.isdigit() else {"value": tlc_val}

                # Static MDR Defaults
                if cf.get("request_type"):
                    fields[cf["request_type"]] = "113"
                if cf.get("assigned_group"):
                    fields[cf["assigned_group"]] = [{"name": "NopalCyber-MDR-L1"}]

                # Attempt Jira Cloud API v3
                endpoint_v3 = f"{base_url}/rest/api/3/issue"
                resp = await client.post(endpoint_v3, auth=auth, headers=headers, json={"fields": fields})

                # Fallback 1: On-premise Jira Data Center / Server (v3 404 -> v2 plain string fallback)
                if resp.status_code == 404:
                    logger.info("Jira v3 returned 404. Retrying with Jira Server/DC API v2...")
                    fields_v2 = fields.copy()
                    fields_v2["description"] = full_description_text
                    if cf.get("threat_description") in fields_v2:
                        fields_v2[cf["threat_description"]] = threat_desc
                    if cf.get("impact") in fields_v2:
                        fields_v2[cf["impact"]] = impact
                    if cf.get("remediation") in fields_v2:
                        fields_v2[cf["remediation"]] = remediation
                    resp = await client.post(f"{base_url}/rest/api/2/issue", auth=auth, headers=headers, json={"fields": fields_v2})

                # Fallback 2: Custom Field Schema Rejection (400 -> Baseline Fields Only)
                elif resp.status_code == 400:
                    logger.warning("Jira v3 issue creation rejected (400). Retrying with safe baseline schema: %s", resp.text)
                    safe_fields: dict[str, Any] = {
                        "project": {"key": project_key},
                        "summary": summary,
                        "description": _text_to_adf(full_description_text),
                        "issuetype": {"name": "Task" if issue_type not in {"Incident", "Task", "Bug"} else issue_type},
                        "priority": {"name": _map_priority(severity_val)},
                        "labels": fields["labels"],
                    }
                    resp = await client.post(endpoint_v3, auth=auth, headers=headers, json={"fields": safe_fields})

                resp.raise_for_status()
                data = resp.json()

                return _result({
                    "success": True,
                    "key": data.get("key"),
                    "id": data.get("id"),
                    "url": f"{base_url}/browse/{data.get('key')}",
                    "self": data.get("self"),
                })

            # -------------------------------------------------------------
            # Tool 2: jira_get_issue
            # -------------------------------------------------------------
            elif name == "jira_get_issue":
                issue_key = _sanitize_text(args.get("issue_key"), "").upper()
                if not issue_key:
                    return _result({"success": False, "error": "'issue_key' is required."})

                endpoint = f"{base_url}/rest/api/3/issue/{issue_key}"
                resp = await client.get(
                    endpoint,
                    auth=auth,
                    headers=headers,
                    params={"fields": "summary,status,priority,assignee,created,updated,description,comment"},
                )

                if resp.status_code == 404:
                    resp = await client.get(
                        f"{base_url}/rest/api/2/issue/{issue_key}",
                        auth=auth,
                        headers=headers,
                        params={"fields": "summary,status,priority,assignee,created,updated,description,comment"},
                    )

                resp.raise_for_status()
                data = resp.json()
                f_data = data.get("fields") or {}

                comments = [
                    {
                        "author": (c.get("author") or {}).get("displayName"),
                        "created": c.get("created"),
                    }
                    for c in (f_data.get("comment") or {}).get("comments", [])[-5:]
                ]

                return _result({
                    "success": True,
                    "key": data.get("key"),
                    "summary": f_data.get("summary"),
                    "status": (f_data.get("status") or {}).get("name"),
                    "priority": (f_data.get("priority") or {}).get("name"),
                    "assignee": (f_data.get("assignee") or {}).get("displayName"),
                    "created": f_data.get("created"),
                    "updated": f_data.get("updated"),
                    "recent_comments": comments,
                    "url": f"{base_url}/browse/{issue_key}",
                })

            # -------------------------------------------------------------
            # Tool 3: jira_search (POST-based JQL)
            # -------------------------------------------------------------
            elif name == "jira_search":
                jql = _sanitize_text(args.get("jql"), "")
                if not jql:
                    return _result({"success": False, "error": "JQL query parameter is required."})

                max_results = min(max(int(args.get("max_results", 10)), 1), 50)
                search_payload = {
                    "jql": jql,
                    "maxResults": max_results,
                    "fields": ["summary", "status", "priority", "assignee", "created", "updated"],
                }

                endpoint = f"{base_url}/rest/api/3/search"
                resp = await client.post(endpoint, auth=auth, headers=headers, json=search_payload)

                if resp.status_code == 404:
                    resp = await client.post(f"{base_url}/rest/api/2/search", auth=auth, headers=headers, json=search_payload)

                resp.raise_for_status()
                data = resp.json()

                issues = [
                    {
                        "key": item.get("key"),
                        "summary": (item.get("fields") or {}).get("summary"),
                        "status": ((item.get("fields") or {}).get("status") or {}).get("name"),
                        "priority": ((item.get("fields") or {}).get("priority") or {}).get("name"),
                        "assignee": ((item.get("fields") or {}).get("assignee") or {}).get("displayName"),
                        "url": f"{base_url}/browse/{item.get('key')}",
                    }
                    for item in data.get("issues", [])
                ]

                return _result({
                    "success": True,
                    "total": data.get("total", len(issues)),
                    "count": len(issues),
                    "issues": issues,
                })

            # -------------------------------------------------------------
            # Tool 4: jira_add_comment
            # -------------------------------------------------------------
            elif name == "jira_add_comment":
                issue_key = _sanitize_text(args.get("issue_key"), "").upper()
                comment_text = _sanitize_text(args.get("comment"), "")
                if not issue_key or not comment_text:
                    return _result({"success": False, "error": "Both 'issue_key' and 'comment' are required."})

                endpoint = f"{base_url}/rest/api/3/issue/{issue_key}/comment"
                resp = await client.post(endpoint, auth=auth, headers=headers, json={"body": _text_to_adf(comment_text)})

                if resp.status_code == 404:
                    resp = await client.post(
                        f"{base_url}/rest/api/2/issue/{issue_key}/comment",
                        auth=auth,
                        headers=headers,
                        json={"body": comment_text},
                    )

                resp.raise_for_status()
                data = resp.json()

                return _result({
                    "success": True,
                    "issue_key": issue_key,
                    "comment_id": data.get("id"),
                    "url": f"{base_url}/browse/{issue_key}",
                })

            # -------------------------------------------------------------
            # Tool 5: jira_transition_issue
            # -------------------------------------------------------------
            elif name == "jira_transition_issue":
                issue_key = _sanitize_text(args.get("issue_key"), "").upper()
                target_transition = _sanitize_text(args.get("transition_name"), "")
                if not issue_key or not target_transition:
                    return _result({"success": False, "error": "Both 'issue_key' and 'transition_name' are required."})

                # Fetch available transitions
                endpoint_trans = f"{base_url}/rest/api/3/issue/{issue_key}/transitions"
                resp = await client.get(endpoint_trans, auth=auth, headers=headers)
                if resp.status_code == 404:
                    endpoint_trans = f"{base_url}/rest/api/2/issue/{issue_key}/transitions"
                    resp = await client.get(endpoint_trans, auth=auth, headers=headers)

                resp.raise_for_status()
                available = resp.json().get("transitions", [])

                matching = next(
                    (t for t in available if str(t.get("name")).lower() == target_transition.lower()),
                    None,
                )
                if not matching:
                    avail_names = [t.get("name") for t in available]
                    return _result({
                        "success": False,
                        "error": f"Transition '{target_transition}' not found. Available transitions: {avail_names}",
                    })

                trans_id = matching.get("id")
                trans_resp = await client.post(
                    endpoint_trans,
                    auth=auth,
                    headers=headers,
                    json={"transition": {"id": trans_id}},
                )
                trans_resp.raise_for_status()

                return _result({
                    "success": True,
                    "issue_key": issue_key,
                    "transition": matching.get("name"),
                    "transition_id": trans_id,
                })

            # -------------------------------------------------------------
            # Tool 6: jira_create_subtask
            # -------------------------------------------------------------
            elif name == "jira_create_subtask":
                parent_key = _sanitize_text(args.get("parent_issue_key"), "").upper()
                summary = _sanitize_text(args.get("summary"), "Remediation Action Task")[:255]
                desc = args.get("description") or ""
                subtask_type = _sanitize_text(args.get("subtask_issue_type") or "Sub-task", "Sub-task")

                if not parent_key or not summary:
                    return _result({"success": False, "error": "'parent_issue_key' and 'summary' are required."})

                # Resolve Project Key
                parent_resp = await client.get(
                    f"{base_url}/rest/api/3/issue/{parent_key}",
                    auth=auth,
                    headers=headers,
                    params={"fields": "project"},
                )
                if parent_resp.status_code == 404:
                    parent_resp = await client.get(
                        f"{base_url}/rest/api/2/issue/{parent_key}",
                        auth=auth,
                        headers=headers,
                        params={"fields": "project"},
                    )

                parent_resp.raise_for_status()
                project_key = parent_resp.json().get("fields", {}).get("project", {}).get("key")

                subtask_payload = {
                    "fields": {
                        "project": {"key": project_key},
                        "parent": {"key": parent_key},
                        "summary": summary,
                        "description": _text_to_adf(desc),
                        "issuetype": {"name": subtask_type},
                    }
                }

                endpoint = f"{base_url}/rest/api/3/issue"
                subtask_resp = await client.post(endpoint, auth=auth, headers=headers, json=subtask_payload)

                if subtask_resp.status_code == 404:
                    subtask_payload["fields"]["description"] = desc
                    subtask_resp = await client.post(f"{base_url}/rest/api/2/issue", auth=auth, headers=headers, json=subtask_payload)
                elif subtask_resp.status_code == 400 and subtask_type == "Sub-task":
                    subtask_payload["fields"]["issuetype"]["name"] = "Subtask"
                    subtask_resp = await client.post(endpoint, auth=auth, headers=headers, json=subtask_payload)

                subtask_resp.raise_for_status()
                data = subtask_resp.json()

                return _result({
                    "success": True,
                    "subtask_key": data.get("key"),
                    "parent_key": parent_key,
                    "url": f"{base_url}/browse/{data.get('key')}",
                })

            return _result({"success": False, "error": f"Unknown tool: {name}"})

        except httpx.HTTPStatusError as e:
            error_body = e.response.text
            logger.error("Jira API HTTP Error status=%d url=%s body=%s", e.response.status_code, e.request.url, error_body)
            return _result({
                "success": False,
                "status_code": e.response.status_code,
                "error": error_body,
            })
        except Exception as e:
            logger.error("Jira MCP Tool Exception in %s: %s", name, e, exc_info=True)
            return _result({
                "success": False,
                "error": str(e),
            })


async def main() -> None:
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(
            read,
            write,
            InitializationOptions(
                server_name="jira",
                server_version="0.3.5",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())