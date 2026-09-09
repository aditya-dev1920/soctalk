"""SocTalk MCP Server for VirusTotal v3 API.

Provides direct threat intelligence lookups for hashes, IPs, domains, and URLs
with built-in RFC1918 private IP filtering, defanging normalization, input validation,
and async rate-limiting.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import os
import re
import time
from typing import Any
from urllib.parse import urlparse

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
logger = logging.getLogger("soctalk.mcp.virustotal")
server = Server("virustotal")


class AsyncTokenBucket:
    """Async token bucket rate limiter for VirusTotal API tier constraints."""

    def __init__(self, requests_per_minute: int = 4) -> None:
        self.capacity = max(1, requests_per_minute)
        self.tokens = float(self.capacity)
        self.rate = self.capacity / 60.0  # Tokens per second
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(float(self.capacity), self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens < 1.0:
                wait_time = (1.0 - self.tokens) / self.rate
                logger.info("VirusTotal rate limit reached. Waiting %.2fs...", wait_time)
                await asyncio.sleep(wait_time)
                self.tokens = 0.0
                self.last_update = time.monotonic()
            else:
                self.tokens -= 1.0


# Rate limit configuration (Default: 4 req/min for free public tier)
_rpm = int(os.getenv("VT_REQUESTS_PER_MIN", os.getenv("VIRUSTOTAL_RPM", "4")))
_limiter = AsyncTokenBucket(requests_per_minute=_rpm)


def _result(data: Any) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


def _get_api_key() -> str:
    return (
        os.getenv("VIRUSTOTAL_API_KEY")
        or os.getenv("VT_API_KEY")
        or os.getenv("VT_APIKEY")
        or ""
    ).strip()


def _refang(text: str) -> str:
    """Normalize and refang defanged indicators (e.g. hxxp://, [.], [:])."""
    s = text.strip()
    s = re.sub(r"^hxxps?", lambda m: "https" if m.group(0).lower() == "hxxps" else "http", s, flags=re.IGNORECASE)
    s = s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    s = s.replace("[:]", ":").replace("(:)", ":").replace("{:}", ":")
    return re.sub(r"\s+", "", s)


async def _vt_api_get(endpoint: str, client: httpx.AsyncClient) -> httpx.Response:
    await _limiter.acquire()
    api_key = _get_api_key()
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "SocTalk-VirusTotal-MCP/0.3.0",
    }
    url = f"https://www.virustotal.com/api/v3/{endpoint.lstrip('/')}"
    return await client.get(url, headers=headers)


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="vt_check_hash",
            description="Check file hash (MD5, SHA1, SHA256) reputation, detection ratios, and malware families in VirusTotal.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hash": {
                        "type": "string",
                        "description": "MD5, SHA1, or SHA256 cryptographic hash string.",
                    }
                },
                "required": ["hash"],
            },
        ),
        types.Tool(
            name="vt_check_ip",
            description="Check IPv4/IPv6 reputation, ASN, country, and malicious vendor detections in VirusTotal (automatically skips private RFC1918 IPs).",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Public IPv4 or IPv6 address string.",
                    }
                },
                "required": ["ip"],
            },
        ),
        types.Tool(
            name="vt_check_domain",
            description="Check domain/FQDN reputation, categorization, and security vendor verdicts in VirusTotal.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain or FQDN (e.g., malicious-domain.com).",
                    }
                },
                "required": ["domain"],
            },
        ),
        types.Tool(
            name="vt_check_url",
            description="Check website URL reputation and scan verdicts in VirusTotal.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Complete HTTP/HTTPS URL string.",
                    }
                },
                "required": ["url"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    api_key = _get_api_key()
    if not api_key:
        return _result({
            "success": False,
            "error": "VirusTotal API key missing. Set VIRUSTOTAL_API_KEY environment variable.",
        })

    args = arguments or {}

    async with httpx.AsyncClient(timeout=20.0) as client:
        try:
            # -------------------------------------------------------------
            # Tool 1: File Hash Lookup
            # -------------------------------------------------------------
            if name in ("vt_check_hash", "virustotal_get_file_report", "scan_hash_with_virustotal"):
                raw_hash = str(
                    args.get("hash")
                    or args.get("file_hash")
                    or args.get("observable")
                    or args.get("ioc")
                    or ""
                ).strip()
                file_hash = _refang(raw_hash).lower()

                if not file_hash or not re.fullmatch(r"^[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}$", file_hash):
                    return _result({
                        "success": False,
                        "error": f"Invalid hash format '{raw_hash}'. Must be MD5 (32), SHA1 (40), or SHA256 (64) hex string.",
                    })

                resp = await _vt_api_get(f"files/{file_hash}", client)
                if resp.status_code == 404:
                    return _result({
                        "success": True,
                        "hash": file_hash,
                        "found": False,
                        "verdict": "unknown",
                        "note": "Hash not seen in VirusTotal database.",
                    })

                resp.raise_for_status()
                data = resp.json().get("data", {})
                attr = data.get("attributes", {})
                stats = attr.get("last_analysis_stats", {})

                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                harmless = int(stats.get("harmless", 0))
                undetected = int(stats.get("undetected", 0))
                total = malicious + suspicious + harmless + undetected

                ratio = (malicious / total) if total > 0 else 0.0
                verdict = "malicious" if (malicious >= 5 or ratio >= 0.2) else ("suspicious" if (malicious > 0 or suspicious > 0) else "clean")

                return _result({
                    "success": True,
                    "hash": file_hash,
                    "found": True,
                    "verdict": verdict,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "total_engines": total,
                    "detection_ratio": f"{malicious}/{total}",
                    "file_type": attr.get("type_description") or attr.get("magic"),
                    "popular_names": (attr.get("names") or [])[:5],
                    "reputation": attr.get("reputation", 0),
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                })

            # -------------------------------------------------------------
            # Tool 2: IP Address Lookup (With RFC1918 Guard)
            # -------------------------------------------------------------
            elif name in ("vt_check_ip", "virustotal_get_ip_report", "analyze_ip_with_virustotal"):
                raw_ip = str(
                    args.get("ip")
                    or args.get("ip_address")
                    or args.get("observable")
                    or args.get("ioc")
                    or ""
                ).strip()
                clean_ip = _refang(raw_ip)

                try:
                    ip_obj = ipaddress.ip_address(clean_ip)
                    if (
                        ip_obj.is_private
                        or ip_obj.is_loopback
                        or ip_obj.is_link_local
                        or ip_obj.is_multicast
                        or ip_obj.is_reserved
                        or ip_obj.is_unspecified
                    ):
                        return _result({
                            "success": True,
                            "ip": clean_ip,
                            "found": False,
                            "is_private": True,
                            "verdict": "clean",
                            "note": "RFC1918 / Private / Loopback / Unspecified IP address. External VT lookup skipped to conserve API rate limits.",
                        })
                except ValueError:
                    return _result({"success": False, "error": f"Invalid IP address format '{raw_ip}'."})

                resp = await _vt_api_get(f"ip_addresses/{clean_ip}", client)
                if resp.status_code == 404:
                    return _result({"success": True, "ip": clean_ip, "found": False, "verdict": "unknown"})

                resp.raise_for_status()
                attr = resp.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})

                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                total = sum(stats.values())
                verdict = "malicious" if malicious >= 3 else ("suspicious" if (malicious > 0 or suspicious > 0) else "clean")

                return _result({
                    "success": True,
                    "ip": clean_ip,
                    "found": True,
                    "verdict": verdict,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total_engines": total,
                    "as_owner": attr.get("as_owner"),
                    "asn": attr.get("asn"),
                    "country": attr.get("country"),
                    "reputation": attr.get("reputation", 0),
                    "permalink": f"https://www.virustotal.com/gui/ip-address/{clean_ip}",
                })

            # -------------------------------------------------------------
            # Tool 3: Domain Lookup (With URL Stripping Guard)
            # -------------------------------------------------------------
            elif name in ("vt_check_domain", "virustotal_get_domain_report", "scan_domain_with_virustotal"):
                raw_domain = str(
                    args.get("domain")
                    or args.get("domain_name")
                    or args.get("observable")
                    or args.get("ioc")
                    or ""
                ).strip()
                clean_domain = _refang(raw_domain).lower()

                # Strip protocol/path if LLM passes a full URL by accident
                if "://" in clean_domain:
                    clean_domain = urlparse(clean_domain).netloc
                clean_domain = clean_domain.split("/")[0].split(":")[0]

                if not clean_domain or "." not in clean_domain:
                    return _result({"success": False, "error": f"Invalid domain format '{raw_domain}'."})

                resp = await _vt_api_get(f"domains/{clean_domain}", client)
                if resp.status_code == 404:
                    return _result({"success": True, "domain": clean_domain, "found": False, "verdict": "unknown"})

                resp.raise_for_status()
                attr = resp.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})

                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                verdict = "malicious" if malicious >= 3 else ("suspicious" if (malicious > 0 or suspicious > 0) else "clean")

                return _result({
                    "success": True,
                    "domain": clean_domain,
                    "found": True,
                    "verdict": verdict,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "categories": attr.get("categories", {}),
                    "registrar": attr.get("registrar"),
                    "reputation": attr.get("reputation", 0),
                    "permalink": f"https://www.virustotal.com/gui/domain/{clean_domain}",
                })

            # -------------------------------------------------------------
            # Tool 4: URL Lookup (Base64 URL Identifier)
            # -------------------------------------------------------------
            elif name in ("vt_check_url", "virustotal_get_url_report", "scan_url_with_virustotal"):
                raw_url = str(
                    args.get("url")
                    or args.get("url_string")
                    or args.get("observable")
                    or args.get("ioc")
                    or ""
                ).strip()
                clean_url = _refang(raw_url)

                if not clean_url.startswith(("http://", "https://")):
                    clean_url = f"http://{clean_url}"

                url_id = base64.urlsafe_b64encode(clean_url.encode()).decode().rstrip("=")
                resp = await _vt_api_get(f"urls/{url_id}", client)

                if resp.status_code == 404:
                    return _result({"success": True, "url": clean_url, "found": False, "verdict": "unknown"})

                resp.raise_for_status()
                attr = resp.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})

                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                verdict = "malicious" if malicious >= 3 else ("suspicious" if (malicious > 0 or suspicious > 0) else "clean")

                return _result({
                    "success": True,
                    "url": clean_url,
                    "found": True,
                    "verdict": verdict,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "reputation": attr.get("reputation", 0),
                    "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                })

            return _result({"success": False, "error": f"Unknown tool: {name}"})

        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403):
                return _result({
                    "success": False,
                    "error": "Invalid or unauthorized VirusTotal API key (HTTP 401/403).",
                })
            elif e.response.status_code == 429:
                return _result({
                    "success": False,
                    "error": "VirusTotal rate limit / quota exceeded (HTTP 429).",
                })
            return _result({
                "success": False,
                "status_code": e.response.status_code,
                "error": e.response.text,
            })
        except Exception as e:
            logger.error("VirusTotal MCP execution error in %s: %s", name, e, exc_info=True)
            return _result({"success": False, "error": str(e)})


async def main() -> None:
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(
            read,
            write,
            InitializationOptions(
                server_name="virustotal",
                server_version="0.3.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())