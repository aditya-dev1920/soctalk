"""Global MCP client bindings for the SocTalk agent.

This module provides startup/shutdown lifecycle management for MCP clients,
following the pattern from Google's mcp-security project.

Now supports database-backed settings from the Settings UI.
"""

from __future__ import annotations

import os
from typing import Optional

import structlog

from soctalk.config import get_config
from soctalk.mcp.client import MCPClient, MCPClientManager
from soctalk.settings_provider import EnabledMCPServers, create_mcp_configs, load_integration_settings_from_env

logger = structlog.get_logger()

# Global client instances
_manager: Optional[MCPClientManager] = None
_wazuh_client: Optional[MCPClient] = None
_cortex_client: Optional[MCPClient] = None
_thehive_client: Optional[MCPClient] = None
_misp_client: Optional[MCPClient] = None
_jira_client: Optional[MCPClient] = None
_virustotal_client: Optional[MCPClient] = None
_abuseipdb_client: Optional[MCPClient] = None


async def bind_clients(mcp_configs: Optional[EnabledMCPServers] = None) -> None:
    """Initialize and connect all MCP clients.

    This should be called at application startup.

    Args:
        mcp_configs: Optional MCP server configurations from database settings.
                    If None, falls back to environment-based config.
    """
    global _manager, _wazuh_client, _cortex_client, _thehive_client, _misp_client, _jira_client, _virustotal_client, _abuseipdb_client

    logger.info("binding_mcp_clients")

    # Clean up any existing instances before creating a new manager
    if _manager is not None:
        await cleanup_clients()

    _manager = MCPClientManager()

    if mcp_configs is not None:
        # Use database-backed settings
        await _bind_from_db_settings(mcp_configs)
    else:
        # Fall back to environment-based config
        await _bind_from_env_config()

    # Log summary
    connected = []
    if _wazuh_client:
        connected.append("wazuh")
    if _cortex_client:
        connected.append("cortex")
    if _thehive_client:
        connected.append("thehive")
    if _misp_client:
        connected.append("misp")
    if _jira_client:
        connected.append("jira")
    if _virustotal_client:
        connected.append("virustotal")
    if _abuseipdb_client:
        connected.append("abuseipdb")

    logger.info(
        "mcp_clients_bound",
        connected=connected,
        count=len(connected),
    )


async def _bind_from_db_settings(mcp_configs: EnabledMCPServers) -> None:
    """Bind MCP clients based on database settings.

    Only connects to servers that are enabled in the Settings UI.

    Args:
        mcp_configs: MCP server configurations from database settings.
    """
    global _wazuh_client, _cortex_client, _thehive_client, _misp_client, _jira_client, _virustotal_client, _abuseipdb_client

    # Connect to Wazuh MCP server (if enabled)
    if mcp_configs.wazuh:
        logger.info("connecting_to_wazuh", config="database_settings")
        try:
            _wazuh_client = await _manager.add_client(mcp_configs.wazuh)
            logger.info("wazuh_connected", tools=_wazuh_client.get_available_tools())
        except Exception as e:
            logger.error("wazuh_connection_failed", error=str(e))
    else:
        logger.info("wazuh_disabled_in_settings")

    # Connect to Cortex MCP server (if enabled)
    if mcp_configs.cortex:
        logger.info("connecting_to_cortex", config="database_settings")
        try:
            _cortex_client = await _manager.add_client(mcp_configs.cortex)
            logger.info("cortex_connected", tools=_cortex_client.get_available_tools())
        except Exception as e:
            logger.error("cortex_connection_failed", error=str(e))
    else:
        logger.info("cortex_disabled_in_settings")

    # Connect to TheHive MCP server (if enabled)
    if mcp_configs.thehive:
        logger.info("connecting_to_thehive", config="database_settings")
        try:
            _thehive_client = await _manager.add_client(mcp_configs.thehive)
            logger.info("thehive_connected", tools=_thehive_client.get_available_tools())
        except Exception as e:
            logger.error("thehive_connection_failed", error=str(e))
    else:
        logger.info("thehive_disabled_in_settings")

    # Connect to MISP MCP server (if enabled)
    if mcp_configs.misp:
        logger.info("connecting_to_misp", config="database_settings")
        try:
            _misp_client = await _manager.add_client(mcp_configs.misp)
            logger.info("misp_connected", tools=_misp_client.get_available_tools())
        except Exception as e:
            logger.error("misp_connection_failed", error=str(e))
    else:
        logger.info("misp_disabled_in_settings")

    # Connect to Jira MCP server (if enabled)
    if mcp_configs.jira:
        logger.info("connecting_to_jira", config="database_settings")
        try:
            _jira_client = await _manager.add_client(mcp_configs.jira)
            logger.info("jira_connected", tools=_jira_client.get_available_tools())
        except Exception as e:
            logger.error("jira_connection_failed", error=str(e))
    else:
        logger.info("jira_disabled_in_settings")

    # Connect to VirusTotal MCP server (if enabled)
    if mcp_configs.virustotal:
        logger.info("connecting_to_virustotal", config="database_settings")
        try:
            _virustotal_client = await _manager.add_client(mcp_configs.virustotal)
            logger.info("virustotal_connected", tools=_virustotal_client.get_available_tools())
        except Exception as e:
            logger.error("virustotal_connection_failed", error=str(e))
    else:
        logger.info("virustotal_disabled_in_settings")

    # Connect to AbuseIPDB MCP server (if enabled)
    if mcp_configs.abuseipdb:
        logger.info("connecting_to_abuseipdb", config="database_settings")
        try:
            _abuseipdb_client = await _manager.add_client(mcp_configs.abuseipdb)
            logger.info("abuseipdb_connected", tools=_abuseipdb_client.get_available_tools())
        except Exception as e:
            logger.error("abuseipdb_connection_failed", error=str(e))
    else:
        logger.info("abuseipdb_disabled_in_settings")


async def _bind_from_env_config() -> None:
    """Bind MCP clients based on environment configuration.

    This is the fallback when database settings are not supplied.
    """
    global _wazuh_client, _cortex_client, _thehive_client, _misp_client, _jira_client, _virustotal_client, _abuseipdb_client

    explicit_flags = any(
        os.getenv(name) is not None
        for name in [
            "WAZUH_ENABLED",
            "CORTEX_ENABLED",
            "THEHIVE_ENABLED",
            "MISP_ENABLED",
            "JIRA_ENABLED",
            "VIRUSTOTAL_ENABLED",
            "ABUSEIPDB_ENABLED",
        ]
    )

    if explicit_flags:
        logger.info("using_env_flags_for_mcp_binding")
        env_settings = load_integration_settings_from_env()
        env_configs = create_mcp_configs(env_settings)
        await _bind_from_db_settings(env_configs)
        return

    config = get_config()
    logger.info("using_legacy_env_config_fallback")

    servers = [
        ("wazuh", config.wazuh_mcp_server),
        ("cortex", config.cortex_mcp_server),
        ("thehive", config.thehive_mcp_server),
        ("misp", config.misp_mcp_server),
        ("jira", config.jira_mcp_server),
        ("virustotal", config.virustotal_mcp_server),
    ]

    for name, srv_config in servers:
        try:
            logger.info(f"connecting_to_{name}", config="environment")
            client = await _manager.add_client(srv_config)
            if name == "wazuh":
                _wazuh_client = client
            elif name == "cortex":
                _cortex_client = client
            elif name == "thehive":
                _thehive_client = client
            elif name == "misp":
                _misp_client = client
            elif name == "jira":
                _jira_client = client
            elif name == "virustotal":
                _virustotal_client = client
        except Exception as e:
            logger.warning(f"{name}_connection_failed", error=str(e))

    logger.info(
        "mcp_clients_bound_from_env",
        wazuh_tools=_wazuh_client.get_available_tools() if _wazuh_client else [],
        cortex_tools=_cortex_client.get_available_tools() if _cortex_client else [],
        thehive_tools=_thehive_client.get_available_tools() if _thehive_client else [],
        misp_tools=_misp_client.get_available_tools() if _misp_client else [],
        jira_tools=_jira_client.get_available_tools() if _jira_client else [],
        virustotal_tools=_virustotal_client.get_available_tools() if _virustotal_client else [],
        abuseipdb_tools=_abuseipdb_client.get_available_tools() if _abuseipdb_client else [],
    )


async def cleanup_clients() -> None:
    """Close all MCP client connections.

    This should be called at application shutdown.
    """
    global _manager, _wazuh_client, _cortex_client, _thehive_client, _misp_client, _jira_client, _virustotal_client, _abuseipdb_client

    logger.info("cleaning_up_mcp_clients")

    if _manager:
        await _manager.close_all()

    _manager = None
    _wazuh_client = None
    _cortex_client = None
    _thehive_client = None
    _misp_client = None
    _jira_client = None
    _virustotal_client = None
    _abuseipdb_client = None

    logger.info("mcp_clients_cleaned_up")


# Lifecycle alias for runs-worker compatibility
unbind_clients = cleanup_clients


def get_wazuh_client() -> Optional[MCPClient]:
    """Get the Wazuh MCP client.

    Returns:
        The Wazuh MCPClient instance, or None if not connected.
    """
    return _wazuh_client


def get_cortex_client() -> Optional[MCPClient]:
    """Get the Cortex MCP client.

    Returns:
        The Cortex MCPClient instance, or None if not connected.
    """
    return _cortex_client


def get_thehive_client() -> Optional[MCPClient]:
    """Get the TheHive MCP client.

    Returns:
        The TheHive MCPClient instance, or None if not connected.
    """
    return _thehive_client


def get_manager() -> Optional[MCPClientManager]:
    """Get the MCP client manager.

    Returns:
        The MCPClientManager instance, or None if not initialized.
    """
    return _manager


def get_misp_client() -> Optional[MCPClient]:
    """Get the MISP MCP client.

    Returns:
        The MISP MCPClient instance, or None if not connected.
    """
    return _misp_client


def get_jira_client() -> Optional[MCPClient]:
    """Get the Jira MCP client.

    Returns:
        The Jira MCPClient instance, or None if not connected.
    """
    return _jira_client


def get_virustotal_client() -> Optional[MCPClient]:
    """Get the VirusTotal MCP client.

    Returns:
        The VirusTotal MCPClient instance, or None if not connected.
    """
    return _virustotal_client


def is_wazuh_enabled() -> bool:
    """Check if Wazuh integration is enabled and connected."""
    return _wazuh_client is not None


def is_cortex_enabled() -> bool:
    """Check if Cortex integration is enabled and connected."""
    return _cortex_client is not None


def is_thehive_enabled() -> bool:
    """Check if TheHive integration is enabled and connected."""
    return _thehive_client is not None


def is_misp_enabled() -> bool:
    """Check if MISP integration is enabled and connected."""
    return _misp_client is not None


def is_jira_enabled() -> bool:
    """Check if Jira integration is enabled and connected."""
    return _jira_client is not None


def is_virustotal_enabled() -> bool:
    """Check if VirusTotal integration is enabled and connected."""
    return _virustotal_client is not None


def get_enabled_integrations() -> list[str]:
    """Get list of enabled integration names."""
    enabled = []
    if _wazuh_client:
        enabled.append("wazuh")
    if _cortex_client:
        enabled.append("cortex")
    if _thehive_client:
        enabled.append("thehive")
    if _misp_client:
        enabled.append("misp")
    if _jira_client:
        enabled.append("jira")
    if _virustotal_client:
        enabled.append("virustotal")
    return enabled
