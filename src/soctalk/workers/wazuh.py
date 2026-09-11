"""Wazuh worker node for SIEM operations."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog

from soctalk.mcp.bindings import get_wazuh_client
from soctalk.models.enums import Phase, Severity
from soctalk.models.investigation import Finding

logger = structlog.get_logger()


async def wazuh_worker_node(state: dict[str, Any]) -> dict[str, Any]:
    """Wazuh worker node - handles SIEM operations.

    This worker can:
    - Poll alerts from Wazuh
    - Get agent information and forensics
    - Retrieve vulnerability data
    - Search logs

    Args:
        state: Current graph state.

    Returns:
        Updated state dictionary.
    """
    logger.info("wazuh_worker_started")

    client = get_wazuh_client()
    if client is None:
        logger.warning("wazuh_client_not_bound_skipping")
        state["last_error"] = "Wazuh client not bound"
        state["last_updated"] = datetime.now().isoformat()
        return state

    investigation = state.get("investigation", {})
    supervisor_decision = state.get("supervisor_decision", {})
    specific_instructions = (supervisor_decision.get("specific_instructions") or "") if supervisor_decision else ""

    try:
        # Execute agent context resolution first
        state = await _get_agent_context(client, state)

        # If instructions mention vulnerability specifically, run vuln check
        if "vulnerability" in specific_instructions.lower() or "vuln" in specific_instructions.lower():
            state = await _get_vulnerabilities(client, state)
        elif "log" in specific_instructions.lower():
            state = await _search_logs(client, state)
        else:
            # Run forensics (processes & ports) by default on the resolved agent
            state = await _get_agent_forensics(client, state)

        state["last_error"] = None
        logger.info("wazuh_worker_completed")

    except Exception as e:
        logger.error("wazuh_worker_error", error=str(e))
        state["last_error"] = f"Wazuh worker error: {str(e)}"
        state["error_count"] = state.get("error_count", 0) + 1

    state["last_updated"] = datetime.now().isoformat()
    return state


async def _get_agent_context(client: Any, state: dict[str, Any]) -> dict[str, Any]:
    """Get context about agents involved in the investigation.

    Args:
        client: Wazuh MCP client.
        state: Current state.

    Returns:
        Updated state.
    """
    investigation = state.get("investigation", {})
    alerts = investigation.get("alerts", [])

    # Resolve agent names or IDs across flat, nested, and state alerts
    agent_targets = set()

    # 1. Check direct alert in state
    top_alert = state.get("alert") or {}
    alerts_to_scan = alerts if alerts else ([top_alert] if top_alert else [])

    for alert in alerts_to_scan:
        agent_field = alert.get("agent")
        if isinstance(agent_field, dict):
            name = agent_field.get("name")
            aid = agent_field.get("id")
            if name and name != "unknown":
                agent_targets.add(str(name))
            elif aid and aid != "unknown":
                agent_targets.add(str(aid))

        # Check standard host fields
        host = alert.get("host") or alert.get("hostname") or alert.get("endpoint_name")
        if host and host != "unknown":
            agent_targets.add(str(host))

    # Fallback to investigation host or default cluster host
    if not agent_targets and investigation.get("host") and investigation.get("host") != "unknown":
        agent_targets.add(str(investigation.get("host")))

    metadata = investigation.get("metadata", {})
    agents_info = metadata.get("agents_info", {})

    # If no targets were present in standard fields, match alert indicators against active agents
    if not agent_targets:
        logger.info("matching_alert_clues_against_active_agents")
        try:
            active_agents = await client.call_tool("get_wazuh_agents", {"status": "active", "limit": 10})
            if active_agents and "Error" not in str(active_agents):
                agents_raw = str(active_agents)
                import json
                alert_text = json.dumps(alerts_to_scan).lower()

                # Iterate through each agent block returned by Wazuh MCP
                for block in agents_raw.split("Agent ID:")[1:]:
                    lines = block.strip().split("\n")
                    aid = lines[0].split()[0].strip()
                    
                    name = next((l.split(":", 1)[1].strip() for l in lines if l.startswith("Name:")), "")
                    ip = next((l.split(":", 1)[1].strip() for l in lines if l.startswith("IP:")), "")

                    # Match specific endpoint name or IP (never match Agent 000 on generic 'manager' headers)
                    target_host_clues = []
                    for a in alerts_to_scan:
                        a_dict = a if isinstance(a, dict) else (a.model_dump() if hasattr(a, "model_dump") else {})
                        target_host_clues.extend([
                            str(a_dict.get("host") or ""),
                            str(a_dict.get("hostname") or ""),
                            str(a_dict.get("endpoint_name") or ""),
                            str((a_dict.get("agent") or {}).get("name") if isinstance(a_dict.get("agent"), dict) else ""),
                            str((a_dict.get("agent") or {}).get("id") if isinstance(a_dict.get("agent"), dict) else ""),
                        ])
                    target_clues_text = " ".join(target_host_clues).lower()

                    is_match = (
                        (name and name.lower() in target_clues_text)
                        or (ip and ip != "127.0.0.1" and ip in alert_text)
                        or (aid == "000" and ("nopal-siem" in target_clues_text or "000" in target_clues_text))
                    )

                    if is_match:
                        target_name = name or f"agent-{aid}"
                        agents_info[target_name] = f"Agent ID: {aid}\nName: {target_name}"
                        logger.info("agent_matched_to_alert", agent_id=aid, agent_name=target_name)
                        break

                if not agents_info:
                    logger.info("alert_not_linked_to_known_agent_skipping_forensics")
                    return state

                metadata["agents_info"] = agents_info
                investigation["metadata"] = metadata
                state["investigation"] = investigation
                return state
        except Exception as e:
            logger.warning("failed_matching_active_agents", error=str(e))
            return state

    metadata = investigation.get("metadata", {})
    agents_info = metadata.get("agents_info", {})

    # Query agent information
    for target in list(agent_targets)[:5]:
        try:
            # If target is numeric, query by agent ID; otherwise query by agent name
            if target.isdigit():
                query_params = {"status": "active", "limit": 1}
            else:
                query_params = {"status": "active", "name": target, "limit": 1}

            result = await client.call_tool("get_wazuh_agents", query_params)

            if result and "Error" not in str(result):
                agents_info[target] = str(result)
                logger.info("agent_context_retrieved", agent=target)
            else:
                # Fallback: Query all active agents to locate by partial host match
                all_agents = await client.call_tool("get_wazuh_agents", {"status": "active", "limit": 10})
                if all_agents:
                    agents_info[target] = str(all_agents)
                    logger.info("agent_context_retrieved_via_active_list", agent=target)

        except Exception as e:
            logger.warning("failed_to_get_agent_info", agent=target, error=str(e))

    metadata["agents_info"] = agents_info
    investigation["metadata"] = metadata
    state["investigation"] = investigation
    return state


# Function to get agent forensics for agent heath and keep alive to get status API and heartbeat in intial triage stage for agent, asset and identity context details
async def _get_agent_forensics(client: Any, state: dict[str, Any]) -> dict[str, Any]:
    """Get forensic data (processes, ports) for agents.

    Args:
        client: Wazuh MCP client.
        state: Current state.

    Returns:
        Updated state with forensic findings.
    """
    investigation = state.get("investigation", {})
    metadata = investigation.get("metadata", {})
    agents_info = metadata.get("agents_info", {})

    findings = investigation.get("findings", [])
    alerts = investigation.get("alerts") or ([state.get("alert")] if state.get("alert") else [])

    # Get agent IDs from metadata
    for agent_name, agent_data in agents_info.items():
        # Parse agent ID from the response
        agent_id = _extract_agent_id(agent_data)
        if not agent_id:
            continue

        # Derive target process from alert details (binary name, service, or rule description)
        target_process = None
        for a in alerts:
            a_dict = a if isinstance(a, dict) else (a.model_dump() if hasattr(a, "model_dump") else {})
            target_process = (
                a_dict.get("process_name")
                or a_dict.get("filename")
                or ("postgres" if "postgres" in str(a_dict).lower() else None)
                or ("ssh" if "ssh" in str(a_dict).lower() else None)
            )
            if target_process:
                break

        # Query running processes filtered by target service/binary
        try:
            query_params: dict[str, Any] = {"agent_id": agent_id, "limit": 50}
            if target_process:
                query_params["search"] = target_process[:32]

            processes_result = await client.call_tool("get_wazuh_agent_processes", query_params)

            if processes_result:
                # Look for suspicious processes
                suspicious = _analyze_processes(processes_result)
                if suspicious:
                    finding = Finding(
                        description=f"Suspicious processes found on {agent_name}",
                        severity=Severity.MEDIUM,
                        evidence=suspicious[:5],
                        recommendations=["Review process execution", "Check parent process chain"],
                    )
                    findings.append(finding.model_dump())
                    logger.info("suspicious_processes_found", agent=agent_name, count=len(suspicious))

        except Exception as e:
            logger.warning("failed_to_get_processes", agent=agent_name, error=str(e))

        # Get listening ports
        try:
            ports_result = await client.call_tool(
                "get_wazuh_agent_ports",
                {"agent_id": agent_id, "protocol": "tcp", "state": "LISTENING", "limit": 50}
            )

            if ports_result:
                # Look for unusual ports
                unusual = _analyze_ports(ports_result)
                if unusual:
                    finding = Finding(
                        description=f"Unusual listening ports on {agent_name}",
                        severity=Severity.LOW,
                        evidence=unusual[:5],
                        recommendations=["Verify port usage is legitimate"],
                    )
                    findings.append(finding.model_dump())

        except Exception as e:
            logger.warning("failed_to_get_ports", agent=agent_name, error=str(e))

    investigation["findings"] = findings
    state["investigation"] = investigation
    return state


async def _get_vulnerabilities(client: Any, state: dict[str, Any]) -> dict[str, Any]:
    """Get vulnerability data for agents.

    Args:
        client: Wazuh MCP client.
        state: Current state.

    Returns:
        Updated state with vulnerability findings.
    """
    investigation = state.get("investigation", {})
    metadata = investigation.get("metadata", {})
    agents_info = metadata.get("agents_info", {})

    findings = investigation.get("findings", [])

    for agent_name, agent_data in agents_info.items():
        agent_id = _extract_agent_id(agent_data)
        if not agent_id:
            continue

        try:
            # Get critical vulnerabilities
            vuln_result = await client.call_tool(
                "get_wazuh_critical_vulnerabilities",
                {"agent_id": agent_id, "limit": 20}
            )

            if vuln_result and "No" not in vuln_result:
                finding = Finding(
                    description=f"Critical vulnerabilities found on {agent_name}",
                    severity=Severity.HIGH,
                    evidence=[vuln_result[:500]],
                    recommendations=[
                        "Prioritize patching critical vulnerabilities",
                        "Assess if vulnerabilities are being exploited",
                    ],
                )
                findings.append(finding.model_dump())
                logger.info("vulnerabilities_found", agent=agent_name)

        except Exception as e:
            logger.warning("failed_to_get_vulnerabilities", agent=agent_name, error=str(e))

    investigation["findings"] = findings
    state["investigation"] = investigation
    return state


async def _search_logs(client: Any, state: dict[str, Any]) -> dict[str, Any]:
    """Search Wazuh manager logs.

    Args:
        client: Wazuh MCP client.
        state: Current state.

    Returns:
        Updated state with log findings.
    """
    investigation = state.get("investigation", {})

    try:
        # Search for error logs
        error_result = await client.call_tool(
            "get_wazuh_manager_error_logs",
            {"limit": 20}
        )

        if error_result:
            metadata = investigation.get("metadata", {})
            metadata["manager_errors"] = error_result
            investigation["metadata"] = metadata

    except Exception as e:
        logger.warning("failed_to_search_logs", error=str(e))

    state["investigation"] = investigation
    return state


def _extract_agent_id(agent_data: str) -> str | None:
    """Extract agent ID from Wazuh response text or JSON structures.

    Args:
        agent_data: Raw agent data string.

    Returns:
        Agent ID formatted as a string or None.
    """
    import re

    # Match JSON key: "id": "001" or "id": 1
    json_match = re.search(r'["\']id["\']\s*:\s*["\']?(\d+)["\']?', agent_data)
    if json_match:
        return json_match.group(1).zfill(3)

    # Match formatted text: "ID: 001" or "Agent: 001"
    match = re.search(r'(?:ID|Agent):\s*(\d+)', agent_data, re.IGNORECASE)
    if match:
        return match.group(1).zfill(3)

    # Match standalone 3-digit agent patterns (e.g. 000, 001)
    generic_match = re.search(r'\b(00\d)\b', agent_data)
    if generic_match:
        return generic_match.group(1)

    return None


def _analyze_processes(processes_text: str) -> list[str]:
    """Analyze processes for suspicious activity with regex word boundaries and kernel thread exclusion.

    Args:
        processes_text: Raw processes text from Wazuh.

    Returns:
        List of suspicious process descriptions.
    """
    import re
    suspicious = []
    suspicious_patterns = [
        r"powershell(?:\.exe)?", r"cmd\.exe", r"wscript(?:\.exe)?", r"cscript(?:\.exe)?",
        r"mshta(?:\.exe)?", r"certutil(?:\.exe)?", r"bitsadmin(?:\.exe)?",
        r"regsvr32(?:\.exe)?", r"rundll32(?:\.exe)?",
        r"\bnc(?:\.exe)?\b", r"\bncat(?:\.exe)?\b", r"\bnetcat(?:\.exe)?\b",
        r"\bcurl(?:\.exe)?\b", r"\bwget(?:\.exe)?\b",
        r"mimikatz", r"procdump", r"psexec",
    ]

    lines = processes_text.lower().split("\n")
    for line in lines:
        # Ignore Linux kernel worker threads and parent PID 2 tasks
        if "ppid: 2" in line or line.strip().startswith(("name: kworker", "name: cpuhp", "name: idle_inject")):
            continue

        for pattern in suspicious_patterns:
            if re.search(pattern, line):
                suspicious.append(f"Suspicious process: {line.strip()[:100]}")
                break

    return suspicious


def _analyze_ports(ports_text: str) -> list[str]:
    """Analyze listening ports for unusual services.

    Args:
        ports_text: Raw ports text from Wazuh.

    Returns:
        List of unusual port descriptions.
    """
    unusual = []
    # Common legitimate ports to ignore
    common_ports = {22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200}

    import re
    port_pattern = r"Port:\s*(\d+)"

    for match in re.finditer(port_pattern, ports_text):
        port = int(match.group(1))
        if port not in common_ports and port > 1024:
            # Extract context around the port
            start = max(0, match.start() - 50)
            end = min(len(ports_text), match.end() + 50)
            context = ports_text[start:end].strip()
            unusual.append(f"Unusual port {port}: {context}")

    return unusual
