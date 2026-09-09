"""Integration settings for MCP servers and notifications.

The Settings UI persists non-secret runtime preferences (enabled flags, URLs, and
toggles) in the database. Secrets (API keys, passwords, webhook URLs) are read
from environment variables only.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

import structlog

from soctalk.config import MCPServerConfig

logger = structlog.get_logger()


@dataclass
class IntegrationSettings:
    """Non-secret integration settings (DB-backed, env-seeded)."""

    # Wazuh SIEM
    wazuh_enabled: bool = False
    wazuh_url: Optional[str] = None
    wazuh_verify_ssl: bool = True

    # Cortex
    cortex_enabled: bool = False
    cortex_url: Optional[str] = None
    cortex_verify_ssl: bool = True

    # TheHive
    thehive_enabled: bool = False
    thehive_url: Optional[str] = None
    thehive_organisation: Optional[str] = None
    thehive_verify_ssl: bool = True

    # MISP
    misp_enabled: bool = False
    misp_url: Optional[str] = None
    misp_verify_ssl: bool = True

    # Jira
    jira_enabled: bool = False
    jira_url: Optional[str] = None
    jira_default_project: Optional[str] = None
    jira_verify_ssl: bool = True

    # VirusTotal
    virustotal_enabled: bool = False
    virustotal_rpm: Optional[int] = None

    # AbuseIPDB
    abuseipdb_enabled: bool = False

    # Slack
    slack_enabled: bool = False
    slack_channel: Optional[str] = None
    slack_notify_on_escalation: bool = True
    slack_notify_on_verdict: bool = True


@dataclass(frozen=True)
class IntegrationSecrets:
    """Secret integration settings (env-only)."""

    wazuh_username: Optional[str] = None
    wazuh_password: Optional[str] = None
    cortex_api_key: Optional[str] = None
    thehive_api_key: Optional[str] = None
    misp_api_key: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    # Jira / VirusTotal secrets
    jira_api_token: Optional[str] = None
    jira_email: Optional[str] = None
    jira_bearer_token: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    # AbuseIPDB
    abuseipdb_api_key: Optional[str] = None


def load_integration_secrets_from_env() -> IntegrationSecrets:
    """Load secret integration settings from environment variables with whitespace stripping."""
    def _clean_env(name: str, *aliases: str) -> Optional[str]:
        for key in (name, *aliases):
            val = os.getenv(key)
            if val is not None and val.strip():
                return val.strip()
        return None

    return IntegrationSecrets(
        wazuh_username=_clean_env("WAZUH_API_USER", "WAZUH_API_USERNAME"),
        wazuh_password=_clean_env("WAZUH_API_PASSWORD"),
        cortex_api_key=_clean_env("CORTEX_API_KEY"),
        thehive_api_key=_clean_env("THEHIVE_API_KEY", "THEHIVE_API_TOKEN"),
        misp_api_key=_clean_env("MISP_API_KEY"),
        slack_webhook_url=_clean_env("SLACK_WEBHOOK_URL"),
        jira_api_token=_clean_env("JIRA_API_TOKEN", "JIRA_PASSWORD", "JIRA_TOKEN"),
        jira_email=_clean_env("JIRA_EMAIL", "JIRA_USERNAME"),
        jira_bearer_token=_clean_env("JIRA_BEARER_TOKEN"),
        virustotal_api_key=_clean_env("VIRUSTOTAL_API_KEY", "VT_API_KEY", "VT_APIKEY"),
        abuseipdb_api_key=_clean_env("ABUSEIPDB_API_KEY"),
    )


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_integration_settings_from_env() -> IntegrationSettings:
    """Load non-secret integration settings from environment variables."""
    wazuh_url = os.getenv("WAZUH_URL")
    if not wazuh_url:
        host = os.getenv("WAZUH_API_HOST")
        port = os.getenv("WAZUH_API_PORT")
        if host and port:
            wazuh_url = f"https://{host}:{port}"

    cortex_url = os.getenv("CORTEX_URL") or os.getenv("CORTEX_ENDPOINT")

    # Jira
    jira_url = os.getenv("JIRA_URL")

    # VirusTotal
    vt_rpm = os.getenv("VT_REQUESTS_PER_MIN") or os.getenv("VIRUSTOTAL_RPM")
    vt_rpm_val = int(vt_rpm) if vt_rpm and vt_rpm.isdigit() else None

    return IntegrationSettings(
        # Wazuh
        wazuh_enabled=_parse_bool(os.getenv("WAZUH_ENABLED"), False),
        wazuh_url=wazuh_url,
        wazuh_verify_ssl=_parse_bool(os.getenv("WAZUH_VERIFY_SSL"), True),
        # Cortex
        cortex_enabled=_parse_bool(os.getenv("CORTEX_ENABLED"), False),
        cortex_url=cortex_url,
        cortex_verify_ssl=_parse_bool(os.getenv("CORTEX_VERIFY_SSL"), True),
        # TheHive
        thehive_enabled=_parse_bool(os.getenv("THEHIVE_ENABLED"), False),
        thehive_url=os.getenv("THEHIVE_URL"),
        thehive_organisation=os.getenv("THEHIVE_ORGANISATION"),
        thehive_verify_ssl=_parse_bool(os.getenv("THEHIVE_VERIFY_SSL"), True),
        # MISP
        misp_enabled=_parse_bool(os.getenv("MISP_ENABLED"), False),
        misp_url=os.getenv("MISP_URL"),
        misp_verify_ssl=_parse_bool(os.getenv("MISP_VERIFY_SSL"), True),
        # Jira
        jira_enabled=_parse_bool(os.getenv("JIRA_ENABLED"), False),
        jira_url=jira_url,
        jira_default_project=os.getenv("JIRA_DEFAULT_PROJECT"),
        jira_verify_ssl=_parse_bool(os.getenv("JIRA_VERIFY_SSL"), True),
        # VirusTotal
        virustotal_enabled=_parse_bool(os.getenv("VIRUSTOTAL_ENABLED"), False),
        virustotal_rpm=vt_rpm_val,
        # AbuseIPDB
        abuseipdb_enabled=_parse_bool(os.getenv("ABUSEIPDB_ENABLED"), False),
        # Slack
        slack_enabled=_parse_bool(os.getenv("SLACK_ENABLED"), False),
        slack_channel=os.getenv("SLACK_CHANNEL"),
        slack_notify_on_escalation=_parse_bool(os.getenv("SLACK_NOTIFY_ON_ESCALATION"), True),
        slack_notify_on_verdict=_parse_bool(os.getenv("SLACK_NOTIFY_ON_VERDICT"), True),
    )


def create_wazuh_mcp_config(settings: IntegrationSettings) -> Optional[MCPServerConfig]:
    """Create Wazuh MCP server config from integration settings.

    Args:
        settings: Integration settings from database.

    Returns:
        MCPServerConfig if Wazuh is enabled and configured, None otherwise.
    """
    if not settings.wazuh_enabled:
        return None

    if not settings.wazuh_url:
        logger.warning("wazuh_enabled_but_url_missing")
        return None

    secrets = load_integration_secrets_from_env()
    if not secrets.wazuh_username or not secrets.wazuh_password:
        logger.warning(
            "wazuh_enabled_but_missing_credentials",
            username=bool(secrets.wazuh_username),
            password=bool(secrets.wazuh_password),
        )
        return None

    url = settings.wazuh_url
    if "://" not in url:
        url = f"https://{url}"

    parsed = urlsplit(url)
    host = parsed.hostname or "localhost"
    port = str(parsed.port or 55000)

    base_path = Path(os.getenv("MCP_SERVERS_BASE_PATH", ".."))

    return MCPServerConfig(
        name="wazuh",
        path=Path(
            os.getenv(
                "WAZUH_MCP_SERVER_PATH",
                str(base_path / "mcp-server-wazuh" / "target" / "release" / "mcp-server-wazuh"),
            )
        ),
        env_vars={
            "WAZUH_API_HOST": host,
            "WAZUH_API_PORT": port,
            "WAZUH_API_USERNAME": secrets.wazuh_username,
            "WAZUH_API_PASSWORD": secrets.wazuh_password,
            "WAZUH_INDEXER_HOST": os.getenv("WAZUH_INDEXER_HOST", host),
            "WAZUH_INDEXER_PORT": os.getenv("WAZUH_INDEXER_PORT", "9200"),
            "WAZUH_INDEXER_USERNAME": os.getenv("WAZUH_INDEXER_USERNAME", "admin"),
            "WAZUH_INDEXER_PASSWORD": os.getenv("WAZUH_INDEXER_PASSWORD", "admin"),
            "WAZUH_VERIFY_SSL": "true" if settings.wazuh_verify_ssl else "false",
        },
    )


def create_cortex_mcp_config(settings: IntegrationSettings) -> Optional[MCPServerConfig]:
    """Create Cortex MCP server config from integration settings.

    Args:
        settings: Integration settings from database.

    Returns:
        MCPServerConfig if Cortex is enabled and configured, None otherwise.
    """
    if not settings.cortex_enabled:
        return None

    secrets = load_integration_secrets_from_env()

    if not settings.cortex_url or not secrets.cortex_api_key:
        logger.warning(
            "cortex_enabled_but_missing_config",
            url=bool(settings.cortex_url),
            api_key=bool(secrets.cortex_api_key),
        )
        return None

    base_path = Path(os.getenv("MCP_SERVERS_BASE_PATH", ".."))

    return MCPServerConfig(
        name="cortex",
        path=Path(
            os.getenv(
                "CORTEX_MCP_SERVER_PATH",
                str(base_path / "mcp-server-cortex" / "target" / "release" / "mcp-server-cortex"),
            )
        ),
        env_vars={
            "CORTEX_ENDPOINT": settings.cortex_url,
            "CORTEX_API_KEY": secrets.cortex_api_key,
            "CORTEX_VERIFY_SSL": "true" if settings.cortex_verify_ssl else "false",
        },
    )


def create_thehive_mcp_config(settings: IntegrationSettings) -> Optional[MCPServerConfig]:
    """Create TheHive MCP server config from integration settings.

    Args:
        settings: Integration settings from database.

    Returns:
        MCPServerConfig if TheHive is enabled and configured, None otherwise.
    """
    if not settings.thehive_enabled:
        return None

    secrets = load_integration_secrets_from_env()

    if not settings.thehive_url or not secrets.thehive_api_key:
        logger.warning(
            "thehive_enabled_but_missing_config",
            url=bool(settings.thehive_url),
            api_key=bool(secrets.thehive_api_key),
        )
        return None

    base_path = Path(os.getenv("MCP_SERVERS_BASE_PATH", ".."))

    env_vars = {
        "THEHIVE_URL": settings.thehive_url,
        "THEHIVE_API_TOKEN": secrets.thehive_api_key,
        "VERIFY_SSL": "true" if settings.thehive_verify_ssl else "false",
    }

    if settings.thehive_organisation:
        env_vars["THEHIVE_ORGANISATION"] = settings.thehive_organisation

    return MCPServerConfig(
        name="thehive",
        path=Path(
            os.getenv(
                "THEHIVE_MCP_SERVER_PATH",
                str(base_path / "mcp-server-thehive" / "target" / "release" / "mcp-server-thehive"),
            )
        ),
        env_vars=env_vars,
    )


def create_misp_mcp_config(settings: IntegrationSettings) -> Optional[MCPServerConfig]:
    """Create MISP MCP server config from integration settings.

    Args:
        settings: Integration settings from database.

    Returns:
        MCPServerConfig if MISP is enabled and configured, None otherwise.
    """
    if not settings.misp_enabled:
        return None

    secrets = load_integration_secrets_from_env()

    if not settings.misp_url or not secrets.misp_api_key:
        logger.warning(
            "misp_enabled_but_missing_config",
            url=bool(settings.misp_url),
            api_key=bool(secrets.misp_api_key),
        )
        return None

    base_path = Path(os.getenv("MCP_SERVERS_BASE_PATH", ".."))

    return MCPServerConfig(
        name="misp",
        path=Path(
            os.getenv(
                "MISP_MCP_SERVER_PATH",
                str(base_path / "mcp-server-misp" / "target" / "release" / "mcp-server-misp"),
            )
        ),
        env_vars={
            "MISP_URL": settings.misp_url,
            "MISP_API_KEY": secrets.misp_api_key,
            "MISP_VERIFY_SSL": "true" if settings.misp_verify_ssl else "false",
        },
    )


def create_jira_mcp_config(settings: IntegrationSettings) -> Optional[MCPServerConfig]:
    """Create Jira MCP server config from integration settings."""
    if not settings.jira_enabled:
        return None

    secrets = load_integration_secrets_from_env()
    jira_url = (settings.jira_url or os.getenv("JIRA_URL", "")).rstrip("/")

    # Require URL and at least one valid auth method (Basic Auth: Email+Token OR Bearer Token)
    has_basic_auth = bool(secrets.jira_email and secrets.jira_api_token)
    has_bearer_auth = bool(secrets.jira_bearer_token)

    if not jira_url or not (has_basic_auth or has_bearer_auth):
        logger.warning(
            "jira_enabled_but_missing_config",
            url=bool(jira_url),
            basic_auth=has_basic_auth,
            bearer_auth=has_bearer_auth,
        )
        return None

    base_path = Path(os.getenv("MCP_SERVERS_BASE_PATH", ".."))

    return MCPServerConfig(
        name="jira",
        path=Path(
            os.getenv(
                "JIRA_MCP_SERVER_PATH",
                str(base_path / "mcp-servers" / "jira" / "jira.py"),
            )
        ),
        env_vars={
            "JIRA_ENABLED": "true",
            "JIRA_URL": jira_url,
            "JIRA_EMAIL": secrets.jira_email or "",
            "JIRA_API_TOKEN": secrets.jira_api_token or "",
            "JIRA_BEARER_TOKEN": secrets.jira_bearer_token or "",
            "JIRA_DEFAULT_PROJECT": settings.jira_default_project or os.getenv("JIRA_DEFAULT_PROJECT") or os.getenv("JIRA_PROJECT_KEY", "SEC"),
            "JIRA_CUSTOM_FIELDS_JSON": os.getenv("JIRA_CUSTOM_FIELDS_JSON", "{}"),
            "JIRA_VERIFY_SSL": "true" if settings.jira_verify_ssl else "false",
        },
    )


def create_virustotal_mcp_config(settings: IntegrationSettings) -> Optional[MCPServerConfig]:
    """Create VirusTotal MCP server config from integration settings."""
    if not settings.virustotal_enabled:
        return None

    secrets = load_integration_secrets_from_env()
    if not secrets.virustotal_api_key:
        logger.warning("virustotal_enabled_but_missing_api_key")
        return None

    base_path = Path(os.getenv("MCP_SERVERS_BASE_PATH", ".."))
    rpm_val = settings.virustotal_rpm or int(os.getenv("VT_REQUESTS_PER_MIN") or os.getenv("VIRUSTOTAL_RPM", "4"))

    return MCPServerConfig(
        name="virustotal",
        path=Path(
            os.getenv(
                "VIRUSTOTAL_MCP_SERVER_PATH",
                str(base_path / "mcp-servers" / "virustotal" / "virustotal.py"),
            )
        ),
        env_vars={
            "VIRUSTOTAL_ENABLED": "true",
            "VIRUSTOTAL_API_KEY": secrets.virustotal_api_key,
            "VT_REQUESTS_PER_MIN": str(rpm_val),
        },
    )


def create_abuseipdb_mcp_config(settings: IntegrationSettings) -> Optional[MCPServerConfig]:
    """Create AbuseIPDB MCP server config from integration settings.

    Args:
        settings: Integration settings from database.

    Returns:
        MCPServerConfig if AbuseIPDB is enabled and configured, None otherwise.
    """
    if not settings.abuseipdb_enabled:
        return None

    secrets = load_integration_secrets_from_env()
    if not secrets.abuseipdb_api_key:
        logger.warning("abuseipdb_enabled_but_missing_api_key")
        return None

    return MCPServerConfig(
        name="abuseipdb",
        path=Path("uvx"),
        args=["mcp-abuseipdb"],
        env_vars={
            "ABUSEIPDB_API_KEY": secrets.abuseipdb_api_key,
        },
    )

    
@dataclass
class EnabledMCPServers:
    """Container for enabled MCP server configurations."""

    wazuh: Optional[MCPServerConfig] = None
    cortex: Optional[MCPServerConfig] = None
    thehive: Optional[MCPServerConfig] = None
    misp: Optional[MCPServerConfig] = None
    jira: Optional[MCPServerConfig] = None
    virustotal: Optional[MCPServerConfig] = None
    abuseipdb: Optional[MCPServerConfig] = None

    @property
    def has_any_enabled(self) -> bool:
        """Check if any MCP server is enabled."""
        return any([self.wazuh, self.cortex, self.thehive, self.misp, self.jira, self.virustotal, self.abuseipdb])

    @property
    def enabled_count(self) -> int:
        """Count of enabled MCP servers."""
        return sum(1 for s in [self.wazuh, self.cortex, self.thehive, self.misp, self.jira, self.virustotal, self.abuseipdb] if s is not None)


def create_mcp_configs(settings: IntegrationSettings) -> EnabledMCPServers:
    """Create MCP server configurations based on integration settings.

    Args:
        settings: Integration settings from database.

    Returns:
        EnabledMCPServers with configs for enabled integrations.
    """
    return EnabledMCPServers(
        wazuh=create_wazuh_mcp_config(settings),
        cortex=create_cortex_mcp_config(settings),
        thehive=create_thehive_mcp_config(settings),
        misp=create_misp_mcp_config(settings),
        jira=create_jira_mcp_config(settings),
        virustotal=create_virustotal_mcp_config(settings),
        abuseipdb=create_abuseipdb_mcp_config(settings),
    )
