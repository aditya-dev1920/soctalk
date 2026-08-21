"""SocTalk per-tenant adapter — heartbeat + Wazuh alert ingest to L1."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI

from soctalk_wire import (
    REDACTION_VERSION,
    SCHEMA_VERSION,
    TEMPLATE_VERSION,
    redact_text,
    template_hash,
)

logger = logging.getLogger("soctalk.adapter")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

VERSION = "0.2.4"

CHECKPOINT_LOAD_MAX_ATTEMPTS = 10
CHECKPOINT_LOAD_RETRY_SECONDS = 6.0


def _read_token() -> str:
    path = Path(os.environ.get("ADAPTER_TOKEN_PATH", "/run/secrets/adapter/token"))
    return path.read_text().strip()


def _initial_alert_ts() -> str:
    raw = os.environ.get("SOCTALK_INGEST_INITIAL_TS", "").strip()
    if not raw:
        return "1970-01-01T00:00:00.000Z"
    if raw.lower() == "now":
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
    return raw


class _State:
    def __init__(self) -> None:
        self.last_heartbeat_ok: datetime | None = None
        self.last_heartbeat_error: str | None = None
        self.last_alert_ts: str = _initial_alert_ts()
        self.last_alert_id: str | None = None
        self.alerts_queried: int = 0
        self.alerts_forwarded: int = 0
        self.alerts_duplicate: int = 0
        self.alerts_dropped_rate_limit: int = 0
        self.batch_seq: int = 0
        self.checkpoint_loaded: bool = False
        self.last_ingest_error: str | None = None


_state = _State()


class _TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = max(rate_per_sec, 0.0)
        self.burst = max(burst, 1)
        self.tokens = float(self.burst)
        self.last = time.monotonic()

    def take(self, n: int) -> tuple[int, int]:
        if self.rate <= 0:
            return n, 0
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
        self.last = now
        allowed = min(n, int(self.tokens))
        self.tokens -= allowed
        return allowed, n - allowed


def _make_rate_limiter() -> _TokenBucket:
    per_min = float(os.environ.get("SOCTALK_ADAPTER_RATE_LIMIT_PER_MIN", "60"))
    burst = int(os.environ.get("SOCTALK_ADAPTER_RATE_LIMIT_BURST", "30"))
    return _TokenBucket(rate_per_sec=per_min / 60.0, burst=burst)


_rate_limiter = _make_rate_limiter()


def _wazuh_indexer_url() -> str:
    return os.environ.get("WAZUH_INDEXER_URL", "https://wazuh-indexer:9200").rstrip("/")


def _wazuh_indexer_creds() -> tuple[str, str]:
    return (
        os.environ.get("WAZUH_INDEXER_USERNAME", "admin"),
        os.environ.get("WAZUH_INDEXER_PASSWORD", "admin"),
    )


def _wazuh_indexer_verify_ssl() -> bool:
    raw = os.environ.get("WAZUH_INDEXER_VERIFY_SSL", "true")
    normalized = raw.strip().lower()
    if normalized in {"true", "1"}:
        return True
    if normalized in {"false", "0"}:
        return False
    logger.warning(
        "WAZUH_INDEXER_VERIFY_SSL=%r is not a recognised boolean; defaulting to verify=True", raw
    )
    return True


def _soctalk_api_verify_ssl() -> bool:
    raw = os.environ.get("SOCTALK_API_VERIFY_SSL", "true")
    normalized = raw.strip().lower()
    if normalized in {"true", "1"}:
        return True
    if normalized in {"false", "0"}:
        return False
    logger.warning(
        "SOCTALK_API_VERIFY_SSL=%r is not a recognised boolean; defaulting to verify=True", raw
    )
    return True


def _severity_from_rule_level(level: int | None) -> int:
    if level is None:
        return 0
    return max(0, min(15, int(level)))


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|tk|xyz|info|biz|online|site|tech|top)\b",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_EMBEDDED_DOMAIN_RE = re.compile(
    r'(?:ldap://|https?://|error=[\$%7B]*jndi:ldap://[^\s/]+/)?([a-zA-Z0-9.-]+\.(?:com|net|org|io|ru|cn|tk|xyz|info|biz|online|site|tech|top))\b',
    re.IGNORECASE,
)


def _is_routable_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b, *_ = (int(p) for p in parts)
    except ValueError:
        return False
    if a in (10, 127, 0):
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    return True


def _extract_iocs(text: str, data: dict | None = None) -> list[dict]:
    if not text and not data:
        return []
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []

    def _add(t: str, v: Any) -> None:
        if not v:
            return
        s = str(v).strip().strip("'\"")
        if not s or s.lower() in ("unknown", "null", "none", "0.0.0.0", "127.0.0.1", "localhost"):
            return
        key = (t, s.lower() if "hash" in t or t in ("domain", "email") else s)
        if key not in seen:
            seen.add(key)
            out.append({"type": t, "value": s if t == "url" else key[1]})

    # 1. Text Regex Scanning
    if text:
        for ip in _IPV4_RE.findall(text):
            if _is_routable_ip(ip):
                _add("ip", ip)
        for h in _SHA256_RE.findall(text):
            _add("hash_sha256", h)
        for h in _MD5_RE.findall(text):
            if not any(k[0] == "hash_sha256" and h.lower() in k[1] for k in seen):
                _add("hash_md5", h)
        for d in _DOMAIN_RE.findall(text):
            if not any(d.lower().endswith(sfx) for sfx in (".local", ".lan")):
                _add("domain", d)
        for u in _URL_RE.findall(text):
            _add("url", u)
        for em in _EMAIL_RE.findall(text):
            _add("email", em)
        for dom in _EMBEDDED_DOMAIN_RE.findall(text):
            if not any(dom.lower().endswith(sfx) for sfx in (".local", ".lan")):
                _add("domain", dom)

    # 2. Dynamic Structured Decoder Fields Extraction
    if isinstance(data, dict):
        # Network IPs
        for ip_field in (
            "srcip", "dstip", "SourceIP", "ClientIP", "source_ip", "destination_ip", "caller_ip_address"
        ):
            ip_val = data.get(ip_field)
            if ip_val and _is_routable_ip(str(ip_val)):
                _add("ip", str(ip_val))

        win_ev = (data.get("win") or {}).get("eventdata") or {}
        for ip_val in (win_ev.get("destinationIp"), win_ev.get("sourceIp")):
            if ip_val and _is_routable_ip(str(ip_val)):
                _add("ip", str(ip_val))

        # Email Artifacts (Office 365, Exchange, Defender)
        for em_field in ("Sender", "Recipient", "UserId", "User", "sender", "recipient", "from", "to"):
            em_val = data.get(em_field)
            if em_val and "@" in str(em_val):
                for em in _EMAIL_RE.findall(str(em_val)):
                    _add("email", em)

        # URLs and Domains
        for url_field in ("url", "URL", "Url", "target_url", "request_url"):
            if data.get(url_field):
                url_str = str(data[url_field])
                _add("url", url_str)
                try:
                    parsed = urlparse(url_str)
                    if parsed.netloc:
                        _add("domain", parsed.netloc.split(":")[0])
                except Exception:
                    pass
                for dom in _EMBEDDED_DOMAIN_RE.findall(url_str):
                    if not any(dom.lower().endswith(sfx) for sfx in (".local", ".lan")):
                        _add("domain", dom)

        if data.get("domain"):
            _add("domain", str(data["domain"]))
        if win_ev.get("queryName"):
            _add("domain", str(win_ev["queryName"]))

        # Hashes
        if win_ev.get("hashes"):
            for part in str(win_ev["hashes"]).split(","):
                if "=" in part:
                    _add("hash_sha256" if "sha256" in part.lower() else "hash_md5", part.split("=", 1)[1])
                else:
                    _add("hash_sha256" if len(part) == 64 else "hash_md5", part)

    return out[:32]


_NAME_KV_RE = re.compile(r"\bname=([A-Za-z0-9_\-.]+)")
_FIM_FILE_RE = re.compile(r"File '([^']+)' (?:was )?(?:modified|added|deleted|changed)", re.I)
_USERID_KV_RE = re.compile(r"\b(?:USER|user|uid)=([A-Za-z0-9_\-.]+)")
_IP_RE = re.compile(r"\b(?:from|src ip|source)\s*[=:]?\s*((?:\d{1,3}\.){3}\d{1,3})", re.I)


def _extract_subject(full_log: str) -> str | None:
    if not full_log:
        return None
    for rx in (_FIM_FILE_RE, _NAME_KV_RE, _USERID_KV_RE, _IP_RE):
        m = rx.search(full_log)
        if m:
            return m.group(1)[:80]
    return None


def _compose_title(rule_desc: str, agent_name: str | None, subject: str | None) -> str:
    base = (rule_desc or "Wazuh alert").strip().rstrip(".")
    if subject:
        base = f"{base}: {subject}"
    if agent_name:
        base = f"{base} on {agent_name}"
    return base[:255]


_ALLOWED_ENTITY_TYPES = {"user", "host", "ip", "process", "hash", "domain", "port"}


def _extract_entities(src: dict, agent: dict, agent_name: str | None) -> list[dict]:
    ents: list[dict] = []

    def add(t: str, v: Any, role: str | None, field: str) -> None:
        if v is None or t not in _ALLOWED_ENTITY_TYPES:
            return
        s = str(v).strip()
        if s and s.lower() not in ("unknown", "null", "none"):
            ents.append({"type": t, "value": s[:512], "role": role, "source_field": field})

    if isinstance(agent, dict) and agent.get("id"):
        add("host", agent.get("name") or agent.get("id"), "target", "agent.name")
        if agent.get("ip"):
            add("ip", agent.get("ip"), "target", "agent.ip")

    data = src.get("data") or {}
    if isinstance(data, dict):
        # Network & Firewalls
        if data.get("devname"):
            add("host", data.get("devname"), "target", "data.devname")
        add("ip", data.get("srcip") or data.get("SourceIP") or data.get("ClientIP"), "src", "data.srcip")
        add("ip", data.get("dstip") or data.get("DestinationIP"), "dst", "data.dstip")
        add("port", data.get("srcport"), "src", "data.srcport")
        add("port", data.get("dstport"), "dst", "data.dstport")

        # Identity & Office 365 / Cloud
        add("user", data.get("srcuser") or data.get("Sender"), "actor", "data.srcuser")
        add("user", data.get("dstuser") or data.get("Recipient"), "target", "data.dstuser")
        add("user", data.get("user") or data.get("UserId"), "actor", "data.user")
        add("process", data.get("process") or data.get("command"), "actor", "data.process")

        # Linux Auditd
        audit = data.get("audit") or {}
        if isinstance(audit, dict):
            add("user", audit.get("uid"), "actor", "data.audit.uid")
            add("user", audit.get("euid"), "actor", "data.audit.euid")
            add("user", audit.get("auid"), "actor", "data.audit.auid")
            add("process", audit.get("exe") or audit.get("command"), "actor", "data.audit.exe")

        # Web & Domains
        if data.get("url") or data.get("URL"):
            url_val = str(data.get("url") or data.get("URL"))
            try:
                parsed = urlparse(url_val)
                if parsed.netloc:
                    add("domain", parsed.netloc.split(":")[0], "target", "data.url")
            except Exception:
                pass
        if data.get("domain"):
            add("domain", data.get("domain"), "target", "data.domain")

        # Windows EventData
        win = data.get("win") or {}
        if isinstance(win, dict):
            ev_data = win.get("eventdata") or {}
            if isinstance(ev_data, dict):
                add("user", ev_data.get("targetUserName") or ev_data.get("subjectUserName"), "target", "win.eventdata.user")
                add("process", ev_data.get("image") or ev_data.get("parentImage"), "actor", "win.eventdata.image")
                add("ip", ev_data.get("sourceIp"), "src", "win.eventdata.sourceIp")
                add("ip", ev_data.get("destinationIp"), "dst", "win.eventdata.destinationIp")
                if ev_data.get("queryName"):
                    add("domain", ev_data.get("queryName"), "target", "win.eventdata.queryName")

    # FIM / Syscheck
    syscheck = src.get("syscheck") or {}
    if isinstance(syscheck, dict):
        if syscheck.get("sha256_after"):
            add("hash", syscheck.get("sha256_after"), "target", "syscheck.sha256_after")
        if syscheck.get("md5_after"):
            add("hash", syscheck.get("md5_after"), "target", "syscheck.md5_after")

    seen: set[tuple] = set()
    out: list[dict] = []
    for e in ents:
        k = (e["type"], e["value"], e["role"])
        if k not in seen:
            seen.add(k)
            out.append(e)
    return out[:64]


def _extract_mitre(rule: dict, data: dict | None = None) -> dict:
    mitre = rule.get("mitre") or (data.get("mitre") if isinstance(data, dict) else {}) or {}
    groups = [str(g).lower() for g in (rule.get("groups") or [])]
    rule_desc = str(rule.get("description") or "").lower()

    ids: list[str] = []
    tactics: list[str] = []
    techniques: list[str] = []

    if isinstance(mitre, dict) and any(mitre.values()):
        def _cap(v: Any) -> list[str]:
            if isinstance(v, list):
                return [str(x)[:32] for x in v if x][:16]
            if v:
                return [str(v)[:32]]
            return []
        ids = _cap(mitre.get("id") or mitre.get("ids"))
        tactics = _cap(mitre.get("tactic") or mitre.get("tactics"))
        techniques = _cap(mitre.get("technique") or mitre.get("techniques"))

    # Dynamic Fallback Heuristics for Unmapped Rules
    if not ids:
        if any(g in groups for g in ("office365", "threatintelligence", "o365", "exchange")) or "phish" in rule_desc:
            ids = ["T1566", "T1566.002", "T1204"]
            tactics = ["initial-access", "execution"]
            techniques = ["Phishing", "Spearphishing Link", "User Execution"]
        elif "vulnerability-detector" in groups:
            ids = ["T1190"]
            tactics = ["initial-access"]
            techniques = ["Exploit Public-Facing Application"]
        elif any(g in groups for g in ("fortigate", "firewall", "ips", "attack")) or "attack" in rule_desc:
            ids = ["T1190", "T1059"]
            tactics = ["initial-access", "execution"]
            techniques = ["Exploit Public-Facing Application", "Command and Scripting Interpreter"]
        elif any(g in groups for g in ("sysmon", "windows", "powershell")):
            ids = ["T1059"]
            tactics = ["execution"]
            techniques = ["Command and Scripting Interpreter"]
        elif any(g in groups for g in ("authentication_failed", "sshd", "pam", "invalid_login")):
            ids = ["T1110"]
            tactics = ["credential-access"]
            techniques = ["Brute Force"]
        elif "syscheck" in groups or "fim" in groups:
            ids = ["T1565"]
            tactics = ["impact"]
            techniques = ["Data Manipulation"]

    return {
        "ids": ids,
        "tactics": tactics,
        "techniques": techniques,
    }


def _extract_action(src: dict, data: dict, full_log: str) -> str | None:
    """Dynamically determine security action / disposition."""
    for field in ("action", "Action", "status", "disposition", "verdict", "Verdict"):
        if data.get(field):
            return str(data[field]).lower()
        if src.get(field):
            return str(src[field]).lower()

    # Dynamic regex parse from log text
    if full_log:
        m = re.search(r'\b(?:action|status|disposition|verdict)=["\']?([a-zA-Z0-9_\-]+)["\']?', full_log, re.I)
        if m:
            return m.group(1).lower()
    return None


def _extract_full_log(src: dict, rule: dict) -> str:
    data = src.get("data") or {}
    base_log = ""

    # 1. Direct root or nested full_log string
    if src.get("full_log"):
        base_log = str(src["full_log"])
    elif isinstance(data, dict):
        if data.get("full_log"):
            base_log = str(data["full_log"])
        elif data.get("raw"):
            base_log = str(data["raw"])
        elif data.get("message"):
            base_log = str(data["message"])
        elif data.get("log"):
            base_log = str(data["log"])
        elif (data.get("win") or {}).get("eventdata", {}).get("commandLine"):
            base_log = str((data.get("win") or {}).get("eventdata", {}).get("commandLine"))
        elif (data.get("audit") or {}).get("command"):
            base_log = str((data.get("audit") or {}).get("command"))

        # Vulnerability Findings
        elif data.get("vulnerability"):
            vuln = data["vulnerability"]
            if isinstance(vuln, dict):
                cve = vuln.get("id") or vuln.get("cve") or "Vulnerability"
                pkg = vuln.get("package", {}).get("name") if isinstance(vuln.get("package"), dict) else vuln.get("package", "")
                ver = vuln.get("package", {}).get("version") if isinstance(vuln.get("package"), dict) else ""
                title = vuln.get("title") or ""
                base_log = f"{cve} affecting {pkg} {ver} - {title}".strip(" -")

    # 2. Dynamic Telemetry Serialization for Short/O365 Logs
    desc = str(rule.get("description") or "")
    if isinstance(data, dict) and data:
        # If base_log is minimal or identical to description, assemble key telemetry fields dynamically
        if not base_log or base_log.strip().rstrip(".") == desc.strip().rstrip("."):
            kv_pairs = [f'{k}="{v}"' if " " in str(v) else f"{k}={v}" for k, v in data.items() if not isinstance(v, (dict, list))]
            if kv_pairs:
                base_log = f"{desc} | Telemetry: {' '.join(kv_pairs)}"
            else:
                base_log = desc

    if not base_log:
        base_log = desc

    # 3. Append Composite Burst history
    prev_output = src.get("previous_output")
    if prev_output:
        firedtimes = rule.get("firedtimes", 1)
        base_log = f"{base_log}\n\n--- PREVIOUS COMPOSITE BURSTS (firedtimes: {firedtimes}) ---\n{prev_output}"

    return base_log


def _hit_to_event(hit: dict) -> dict | None:
    src = hit.get("_source") or {}
    source_id = src.get("id") or hit.get("_id")
    if not source_id:
        return None
    rule = src.get("rule") or {}
    agent = src.get("agent") or {}
    data = src.get("data") if isinstance(src.get("data"), dict) else {}
    rule_desc = rule.get("description") or ""
    agent_name = agent.get("name") if isinstance(agent, dict) else None
    agent_id = str(agent.get("id") or "") if isinstance(agent, dict) else ""
    asset_ids: list[str] = []
    if agent_id:
        asset_ids.append(agent_id[:64])
    if agent_name:
        asset_ids.append(agent_name[:64])

    if data.get("devname"):
        dev = str(data["devname"])[:64]
        if dev not in asset_ids:
            asset_ids.append(dev)

    full_log = _extract_full_log(src, rule)
    iocs = _extract_iocs(f"{rule_desc} {full_log}", data)
    entities = _extract_entities(src, agent, agent_name)
    action = _extract_action(src, data, full_log)

    if agent_id == "000":
        dev_m = re.search(r'\b(?:devname|hostname|host|dvc)=["\']?([A-Za-z0-9_\-.]{3,64})["\']?', full_log)
        if dev_m:
            resolved_dev = dev_m.group(1)[:64]
            if resolved_dev not in asset_ids:
                asset_ids.append(resolved_dev)

    full_log_red = redact_text(full_log)[:4096] if full_log else ""
    rule_desc_red = redact_text(rule_desc)[:512] if rule_desc else ""
    description = rule_desc_red or redact_text(full_log.strip())[:1024] or None
    title = redact_text(_compose_title(rule_desc, agent_name, _extract_subject(full_log)))
    thash = template_hash(full_log_red)

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return {
        "source_event_id": str(source_id)[:128],
        "source": "wazuh",
        "rule_id": (str(rule.get("id"))[:64] if rule.get("id") else None),
        "severity": _severity_from_rule_level(rule.get("level")),
        "asset_ids": asset_ids[:8],
        "initial_iocs": iocs,
        "ts": src.get("@timestamp") or src.get("timestamp"),
        "observed_at": now_iso,
        "description": description,
        "title": title,
        "action": action,
        "entities": entities,
        "mitre": _extract_mitre(rule, data),
        "rule_groups": [str(g)[:64] for g in (rule.get("groups") or [])][:16],
        "decoder": (src.get("decoder") or {}).get("name"),
        "full_log": full_log_red,
        "template_hash": thash,
        "template_version": TEMPLATE_VERSION,
        "redaction_version": REDACTION_VERSION,
        "raw": {
            "rule_description": rule_desc_red,
            "rule_groups": rule.get("groups") or [],
            "decoder_name": (src.get("decoder") or {}).get("name"),
            "decoder_parent": (src.get("decoder") or {}).get("parent"),
            "location": src.get("location"),
            "manager_name": (src.get("manager") or {}).get("name"),
            "full_log": full_log_red,
            "action": action,
            "firedtimes": rule.get("firedtimes", 1),
            "raw_source": src,
        },
    }


def _min_severity() -> int:
    raw = os.environ.get("SOCTALK_ADAPTER_MIN_SEVERITY", "5")
    try:
        v = int(raw)
    except ValueError:
        return 5
    return max(0, min(15, v))


async def _query_alerts(
    client: httpx.AsyncClient, since_ts: str, since_id: str | None, limit: int
) -> list[dict]:
    user, pw = _wazuh_indexer_creds()
    filters: list[dict] = [
        {"range": {"@timestamp": {"gte": since_ts}}},
        {"range": {"rule.level": {"gte": _min_severity()}}},
    ]
    must_not: list[dict] = []
    if os.environ.get("SOCTALK_ADAPTER_EXCLUDE_MANAGER_AGENT", "0") in {"1", "true"}:
        must_not.append({"term": {"agent.id": "000"}})
    prefix = os.environ.get("SOCTALK_ADAPTER_AGENT_PREFIX")
    if prefix:
        filters.append({"prefix": {"agent.name": prefix}})
    bool_query: dict = {"filter": filters}
    if must_not:
        bool_query["must_not"] = must_not
    body: dict = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "asc"}}, {"id": {"order": "asc"}}],
        "query": {"bool": bool_query},
    }
    if since_id is not None:
        body["search_after"] = [since_ts, since_id]
    resp = await client.post(
        f"{_wazuh_indexer_url()}/wazuh-alerts-*/_search",
        auth=(user, pw),
        json=body,
        timeout=15.0,
    )
    resp.raise_for_status()
    data = resp.json()
    return list(data.get("hits", {}).get("hits", []))


async def _load_checkpoint(
    client: httpx.AsyncClient, api_url: str, tenant_id: str, token: str
) -> None:
    try:
        resp = await client.get(
            f"{api_url}/api/internal/adapter/checkpoint?source=wazuh",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        cp = resp.json()
        if cp.get("cursor_ts"):
            _state.last_alert_ts = cp["cursor_ts"]
        _state.last_alert_id = cp.get("cursor_event_id")
        _state.batch_seq = int(cp.get("batch_seq") or 0)
        _state.checkpoint_loaded = True
        logger.info(
            "checkpoint_loaded cursor=%s id=%s batch_seq=%d",
            _state.last_alert_ts,
            _state.last_alert_id,
            _state.batch_seq,
        )
    except Exception as e:
        logger.warning("checkpoint_load_failed: %s (starting from local cursor)", e)


async def _save_checkpoint(
    client: httpx.AsyncClient,
    api_url: str,
    tenant_id: str,
    token: str,
    cursor_ts: str,
    cursor_event_id: str | None,
) -> None:
    try:
        resp = await client.put(
            f"{api_url}/api/internal/adapter/checkpoint",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "tenant_id": tenant_id,
                "source": "wazuh",
                "cursor_ts": cursor_ts,
                "cursor_event_id": cursor_event_id,
                "batch_seq": _state.batch_seq,
                "dropped_total": _state.alerts_dropped_rate_limit,
            },
            timeout=10.0,
        )
        resp.raise_for_status()
    except Exception as e:
        logger.warning("checkpoint_save_failed: %s", e)


async def _heartbeat_once(client: httpx.AsyncClient) -> None:
    api_url = os.environ["SOCTALK_API_URL"].rstrip("/")
    tenant_id = os.environ["SOCTALK_TENANT_ID"]
    token = _read_token()
    metrics = {
        "alerts_queried": _state.alerts_queried,
        "alerts_forwarded": _state.alerts_forwarded,
        "alerts_duplicate": _state.alerts_duplicate,
        "alerts_dropped_rate_limit": _state.alerts_dropped_rate_limit,
        "batch_seq": _state.batch_seq,
        "last_alert_ts": _state.last_alert_ts,
        "last_ingest_error": _state.last_ingest_error,
    }
    resp = await client.post(
        f"{api_url}/api/internal/adapter/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json={"tenant_id": tenant_id, "version": VERSION, "health": "ok", "metrics": metrics},
        timeout=10.0,
    )
    resp.raise_for_status()


async def _heartbeat_loop() -> None:
    interval = float(os.environ.get("SOCTALK_HEARTBEAT_INTERVAL_SECONDS", "30"))
    async with httpx.AsyncClient(verify=_soctalk_api_verify_ssl()) as client:
        while True:
            try:
                await _heartbeat_once(client)
                _state.last_heartbeat_ok = datetime.now(timezone.utc)
                _state.last_heartbeat_error = None
                logger.info("heartbeat_ok")
            except Exception as e:
                _state.last_heartbeat_error = str(e)
                logger.warning("heartbeat_failed: %s", e)
            await asyncio.sleep(interval)


async def _ingest_loop() -> None:
    if os.environ.get("SOCTALK_INGEST_DISABLED", "0") in {"1", "true"}:
        logger.info("ingest_disabled")
        return
    interval = float(os.environ.get("SOCTALK_INGEST_INTERVAL_SECONDS", "60"))
    batch_size = int(os.environ.get("SOCTALK_INGEST_BATCH_SIZE", "100"))
    api_url = os.environ["SOCTALK_API_URL"].rstrip("/")
    tenant_id = os.environ["SOCTALK_TENANT_ID"]
    token = _read_token()

    verify_indexer_tls = _wazuh_indexer_verify_ssl()
    verify_api_tls = _soctalk_api_verify_ssl()
    async with (
        httpx.AsyncClient(verify=verify_api_tls) as api_client,
        httpx.AsyncClient(verify=verify_indexer_tls) as wazuh_client,
    ):
        for _attempt in range(CHECKPOINT_LOAD_MAX_ATTEMPTS):
            await _load_checkpoint(api_client, api_url, tenant_id, _read_token())
            if _state.checkpoint_loaded:
                break
            await asyncio.sleep(CHECKPOINT_LOAD_RETRY_SECONDS)
        else:
            logger.warning(
                "checkpoint_never_loaded attempts=%d — starting from local cursor",
                CHECKPOINT_LOAD_MAX_ATTEMPTS,
            )
        while True:
            token = _read_token()
            try:
                hits = await _query_alerts(
                    wazuh_client, _state.last_alert_ts, _state.last_alert_id, batch_size
                )
                _state.alerts_queried += len(hits)
                if hits:
                    events: list[dict] = []
                    for h in hits:
                        ev = _hit_to_event(h)
                        if ev is not None:
                            events.append(ev)

                    new_cursor_ts = _state.last_alert_ts
                    new_cursor_id = _state.last_alert_id
                    if events:
                        last = events[-1]
                        new_cursor_ts = last["ts"] or new_cursor_ts
                        new_cursor_id = last["source_event_id"]

                    if events:
                        allowed, dropped = _rate_limiter.take(len(events))
                        if dropped > 0:
                            _state.alerts_dropped_rate_limit += dropped
                            logger.warning(
                                "rate_limited dropped=%d total_dropped=%d batch=%d",
                                dropped,
                                _state.alerts_dropped_rate_limit,
                                len(events),
                            )
                        events = events[:allowed]

                    if events:
                        _state.batch_seq += 1
                        resp = await api_client.post(
                            f"{api_url}/api/internal/adapter/events",
                            headers={"Authorization": f"Bearer {token}"},
                            json={
                                "tenant_id": tenant_id,
                                "events": events,
                                "schema_version": SCHEMA_VERSION,
                                "batch_seq": _state.batch_seq,
                            },
                            timeout=30.0,
                        )
                        resp.raise_for_status()
                        body = resp.json()
                        dup = (body.get("action_counts") or {}).get("duplicate", 0)
                        _state.alerts_duplicate += dup
                        _state.alerts_forwarded += len(events) - dup
                        _state.last_ingest_error = None

                    if (new_cursor_ts, new_cursor_id) != (
                        _state.last_alert_ts,
                        _state.last_alert_id,
                    ):
                        _state.last_alert_ts = new_cursor_ts
                        _state.last_alert_id = new_cursor_id
                        await _save_checkpoint(
                            api_client,
                            api_url,
                            tenant_id,
                            token,
                            new_cursor_ts,
                            new_cursor_id,
                        )
                        logger.info(
                            "ingest_ok forwarded=%d duplicate=%d total=%d cursor=%s/%s",
                            _state.alerts_forwarded,
                            _state.alerts_duplicate,
                            _state.alerts_forwarded,
                            new_cursor_ts,
                            new_cursor_id,
                        )
            except httpx.HTTPStatusError as e:
                error_detail = e.response.text
                _state.last_ingest_error = f"{e} | Response: {error_detail}"
                logger.error(
                    "ingest_http_error status=%d url=%s response=%s sample_event=%s",
                    e.response.status_code,
                    e.request.url,
                    error_detail,
                    events[0] if "events" in locals() and events else "None",
                )
            except Exception as e:
                _state.last_ingest_error = str(e)
                logger.warning("ingest_failed: %s", e)
            await asyncio.sleep(interval)


@contextlib.asynccontextmanager
async def _lifespan(app: FastAPI):
    del app
    hb = asyncio.create_task(_heartbeat_loop(), name="adapter-heartbeat")
    ig = asyncio.create_task(_ingest_loop(), name="adapter-ingest")
    try:
        yield
    finally:
        for t in (hb, ig):
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await t


app = FastAPI(lifespan=_lifespan)


@app.get("/health/live")
async def live() -> dict:
    return {"ok": True, "version": VERSION}


@app.get("/health/ready")
async def ready() -> dict:
    return {
        "ok": True,
        "last_heartbeat_ok": _state.last_heartbeat_ok.isoformat()
        if _state.last_heartbeat_ok
        else None,
        "last_heartbeat_error": _state.last_heartbeat_error,
        "alerts_queried": _state.alerts_queried,
        "alerts_forwarded": _state.alerts_forwarded,
        "alerts_duplicate": _state.alerts_duplicate,
        "alerts_dropped_rate_limit": _state.alerts_dropped_rate_limit,
        "batch_seq": _state.batch_seq,
        "checkpoint_loaded": _state.checkpoint_loaded,
        "last_alert_ts": _state.last_alert_ts,
        "last_ingest_error": _state.last_ingest_error,
    }
