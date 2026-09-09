"""Cortex worker node for threat intelligence enrichment (with native VirusTotal delegation)."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

import structlog

from soctalk.mcp.bindings import get_cortex_client, get_virustotal_client
from soctalk.models.enums import ObservableType, Phase, Verdict
from soctalk.models.observables import EnrichmentResult, Observable

logger = structlog.get_logger()

# Mapping of observable types to threat intel tools
ANALYZER_MAP = {
    ObservableType.IP: [
        ("vt_check_ip", "VirusTotal"),
        ("analyze_ip_with_abuseipdb", "AbuseIPDB"),
    ],
    ObservableType.URL: [
        ("vt_check_url", "VirusTotal"),
        ("scan_url_with_virustotal", "VirusTotal"),
    ],
    ObservableType.HASH_MD5: [
        ("vt_check_hash", "VirusTotal"),
        ("scan_hash_with_virustotal", "VirusTotal"),
    ],
    ObservableType.HASH_SHA1: [
        ("vt_check_hash", "VirusTotal"),
        ("scan_hash_with_virustotal", "VirusTotal"),
    ],
    ObservableType.HASH_SHA256: [
        ("vt_check_hash", "VirusTotal"),
        ("scan_hash_with_virustotal", "VirusTotal"),
    ],
    ObservableType.DOMAIN: [
        ("vt_check_domain", "VirusTotal"),
        ("analyze_with_abusefinder", "AbuseFinder"),
    ],
    ObservableType.FQDN: [
        ("vt_check_domain", "VirusTotal"),
        ("analyze_with_abusefinder", "AbuseFinder"),
    ],
    ObservableType.EMAIL: [
        ("vt_check_domain", "VirusTotal"),
    ],
}


async def cortex_worker_node(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Cortex worker node - handles threat intelligence enrichment.

    Delegates observables directly to VirusTotal MCP (or Cortex analyzers if enabled):
    - Hash analysis (vt_check_hash)
    - IP reputation (vt_check_ip)
    - Domain / FQDN reputation (vt_check_domain)
    - URL analysis (vt_check_url)
    """
    logger.info("cortex_worker_started")

    client = get_cortex_client()
    vt_client = get_virustotal_client()
    investigation = state.get("investigation", {})
    pending_observables = state.get("pending_observables", [])

    # Convert dict observables back to Observable objects if needed
    observables_to_process = []
    for obs in pending_observables[:10]:  # Process up to 10 at a time
        if isinstance(obs, dict):
            observables_to_process.append(Observable(**obs))
        else:
            observables_to_process.append(obs)

    if not observables_to_process:
        logger.info("no_observables_to_enrich")
        state["current_phase"] = Phase.ANALYSIS.value
        return state

    enrichments = investigation.get("enrichments", [])
    processed_values = set()

    # Deduplicate: skip observables already enriched in previous phases
    existing_enriched_values = set()
    for e in enrichments:
        if isinstance(e, dict):
            ov = e.get("observable")
            if isinstance(ov, dict):
                v = ov.get("value")
                if v:
                    existing_enriched_values.add(v)

    for observable in observables_to_process:
        if observable.value in processed_values:
            continue

        logger.info(
            "enriching_observable",
            type=observable.type.value,
            value=observable.value[:50],
        )

        # Skip if already enriched
        if observable.value in existing_enriched_values:
            logger.info("skip_enrichment_already_present", value=observable.value[:50])
            processed_values.add(observable.value)
            continue

        try:
            enrichment = await _enrich_observable(client, vt_client, observable, investigation)

            if enrichment:
                enrichments.append(enrichment.model_dump())
                processed_values.add(observable.value)

        except Exception as e:
            logger.warning(
                "enrichment_failed",
                observable=observable.value[:50],
                error=str(e),
            )

            failed_enrichment = EnrichmentResult(
                observable=observable,
                analyzer="VirusTotal",
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                error=str(e),
            )
            enrichments.append(failed_enrichment.model_dump())
            processed_values.add(observable.value)

    # Update state
    investigation["enrichments"] = enrichments

    new_pending = [
        o for o in pending_observables
        if (o.get("value") if isinstance(o, dict) else o.value) not in processed_values
    ]

    state["investigation"] = investigation
    state["pending_observables"] = new_pending
    state["current_enrichment_batch"] = []
    state["last_updated"] = datetime.now().isoformat()

    if not new_pending:
        state["current_phase"] = Phase.ANALYSIS.value

    logger.info(
        "cortex_worker_completed",
        enriched=len(processed_values),
        remaining=len(new_pending),
    )

    return state


async def _enrich_observable(
    client: Any,
    vt_client: Any,
    observable: Observable,
    investigation: dict[str, Any],
) -> EnrichmentResult:
    """Enrich an observable using direct VirusTotal MCP lookups or Cortex fallback."""
    effective_client = vt_client or client
    if effective_client is None:
        logger.warning("no_mcp_client_available", observable=observable.value)
        return EnrichmentResult(
            observable=observable,
            analyzer="VirusTotal",
            verdict=Verdict.UNKNOWN,
            confidence=0.0,
            details={"note": "No MCP client available for enrichment"},
        )

    # Route to VirusTotal MCP tools
    if effective_client is vt_client or client is None:
        analyzer_name = "VirusTotal"
        if observable.type in (ObservableType.HASH_MD5, ObservableType.HASH_SHA1, ObservableType.HASH_SHA256):
            tool_to_call = "vt_check_hash"
            args = {"hash": observable.value}
        elif observable.type == ObservableType.IP:
            tool_to_call = "vt_check_ip"
            args = {"ip": observable.value}
        elif observable.type in (ObservableType.DOMAIN, ObservableType.FQDN, ObservableType.EMAIL):
            tool_to_call = "vt_check_domain"
            args = {"domain": observable.value}
        elif observable.type == ObservableType.URL:
            tool_to_call = "vt_check_url"
            args = {"url": observable.value}
        else:
            tool_to_call = "vt_check_domain"
            args = {"domain": observable.value}
    else:
        # Legacy Cortex Server fallback
        analyzers = ANALYZER_MAP.get(observable.type, [])
        tool_to_call, analyzer_name = analyzers[0] if analyzers else ("scan_hash_with_virustotal", "VirusTotal")
        args = {"data": observable.value, "max_retries": 15}

    # Dedup cache check
    cache = investigation.setdefault("enrichment_cache", {})
    cache_key = f"{tool_to_call}:{observable.value}"
    if cache_key in cache:
        logger.info("enrichment_cache_hit", key=cache_key)
        verdict, confidence, details = _parse_enrichment_result(cache[cache_key], tool_to_call)
        return EnrichmentResult(
            observable=observable,
            analyzer=analyzer_name,
            verdict=verdict,
            confidence=confidence,
            details=details,
        )

    result = await effective_client.call_tool(tool_to_call, args)

    try:
        rl = str(result or "").lower()
        if "rate limit" not in rl and "http 429" not in rl:
            cache[cache_key] = result
    except Exception:
        pass

    verdict, confidence, details = _parse_enrichment_result(result, tool_to_call)

    return EnrichmentResult(
        observable=observable,
        analyzer=analyzer_name,
        verdict=verdict,
        confidence=confidence,
        details=details,
    )


def _parse_enrichment_result(
    result: Any, tool_name: str
) -> tuple[Verdict, float, dict[str, Any]]:
    """Parse enrichment result and determine normalized verdict and confidence score."""
    details: dict[str, Any] = {}

    if isinstance(result, dict):
        details = result
    elif isinstance(result, str):
        try:
            if result.strip().startswith("{"):
                details = json.loads(result)
            else:
                details = {"raw_result": result[:1000]}
        except json.JSONDecodeError:
            details = {"raw_result": result[:1000]}
    else:
        details = {"raw_result": str(result)[:1000]}

    # 1. Direct Structured Parsing from VirusTotal MCP
    if isinstance(details, dict) and "verdict" in details:
        v_str = str(details.get("verdict", "")).lower()
        if v_str == "malicious":
            mal_count = int(details.get("malicious", 1))
            total = int(details.get("total_engines", 70)) or 70
            confidence = min(0.99, max(0.75, (mal_count / total) + 0.5))
            return Verdict.MALICIOUS, confidence, details
        elif v_str == "suspicious":
            return Verdict.SUSPICIOUS, 0.65, details
        elif v_str == "clean":
            return Verdict.BENIGN, 0.85, details

    # 2. Heuristic text fallback
    verdict = Verdict.UNKNOWN
    confidence = 0.5
    raw_str = str(result or "").lower()

    if "malicious" in raw_str:
        ratio_match = re.search(r"(\d+)/(\d+)", raw_str)
        if ratio_match:
            detections = int(ratio_match.group(1))
            total = int(ratio_match.group(2))
            ratio = detections / total if total > 0 else 0.0
            if ratio >= 0.2:
                verdict = Verdict.MALICIOUS
                confidence = min(0.95, 0.5 + ratio)
            elif ratio >= 0.05:
                verdict = Verdict.SUSPICIOUS
                confidence = 0.6
            else:
                verdict = Verdict.BENIGN
                confidence = 0.8
        else:
            verdict = Verdict.SUSPICIOUS
            confidence = 0.6
    elif "clean" in raw_str or "harmless" in raw_str:
        verdict = Verdict.BENIGN
        confidence = 0.85

    return verdict, confidence, details



# """Cortex worker node for threat intelligence enrichment."""

# from __future__ import annotations

# import json
# from datetime import datetime
# from typing import Any

# import structlog

# from soctalk.mcp.bindings import get_cortex_client, get_virustotal_client
# from soctalk.models.enums import ObservableType, Verdict, Phase
# from soctalk.models.observables import Observable, EnrichmentResult

# logger = structlog.get_logger()

# # Mapping of observable types to Cortex analyzers
# ANALYZER_MAP = {
#     ObservableType.IP: [
#         ("analyze_ip_with_abuseipdb", "AbuseIPDB"),
#     ],
#     ObservableType.URL: [
#         ("scan_url_with_virustotal", "VirusTotal"),
#         ("analyze_url_with_urlscan_io", "Urlscan.io"),
#     ],
#     ObservableType.HASH_MD5: [
#         ("scan_hash_with_virustotal", "VirusTotal"),
#     ],
#     ObservableType.HASH_SHA1: [
#         ("scan_hash_with_virustotal", "VirusTotal"),
#     ],
#     ObservableType.HASH_SHA256: [
#         ("scan_hash_with_virustotal", "VirusTotal"),
#     ],
#     ObservableType.DOMAIN: [
#         ("analyze_with_abusefinder", "AbuseFinder"),
#     ],
#     ObservableType.EMAIL: [
#         ("analyze_with_abusefinder", "AbuseFinder"),
#     ],
#     ObservableType.FQDN: [
#         ("analyze_with_abusefinder", "AbuseFinder"),
#     ],
# }


# async def cortex_worker_node(
#     state: dict[str, Any],
# ) -> dict[str, Any]:
#     """Cortex worker node - handles threat intelligence enrichment.

#     This worker enriches observables using Cortex analyzers:
#     - IP reputation (AbuseIPDB)
#     - URL scanning (VirusTotal, Urlscan.io)
#     - Hash analysis (VirusTotal)
#     - Domain/email analysis (AbuseFinder)

#     Args:
#         state: Current graph state.

#     Returns:
#         Updated state dictionary.
#     """
#     logger.info("cortex_worker_started")

#     client = get_cortex_client()
#     vt_client = get_virustotal_client()
#     investigation = state.get("investigation", {})
#     pending_observables = state.get("pending_observables", [])

#     # Convert dict observables back to Observable objects if needed
#     observables_to_process = []
#     for obs in pending_observables[:10]:  # Process up to 10 at a time
#         if isinstance(obs, dict):
#             observables_to_process.append(Observable(**obs))
#         else:
#             observables_to_process.append(obs)

#     if not observables_to_process:
#         logger.info("no_observables_to_enrich")
#         state["current_phase"] = Phase.ANALYSIS.value
#         return state

#     enrichments = investigation.get("enrichments", [])
#     processed_values = set()

#     # Deduplicate: skip observables already enriched in previous phases
#     existing_enriched_values = set()
#     for e in enrichments:
#         if isinstance(e, dict):
#             ov = e.get("observable")
#             if isinstance(ov, dict):
#                 v = ov.get("value")
#                 if v:
#                     existing_enriched_values.add(v)

#     for observable in observables_to_process:
#         if observable.value in processed_values:
#             continue

#         logger.info(
#             "enriching_observable",
#             type=observable.type.value,
#             value=observable.value[:50],
#         )

#         # Skip if we've already enriched this observable earlier
#         if observable.value in existing_enriched_values:
#             logger.info("skip_enrichment_already_present", value=observable.value[:50])
#             processed_values.add(observable.value)
#             continue

#         try:
#             enrichment = await _enrich_observable(client, vt_client, observable, investigation)

#             if enrichment:
#                 enrichments.append(enrichment.model_dump())
#                 processed_values.add(observable.value)

#         except Exception as e:
#             logger.warning(
#                 "enrichment_failed",
#                 observable=observable.value[:50],
#                 error=str(e),
#             )

#             # Add a failed enrichment result
#             failed_enrichment = EnrichmentResult(
#                 observable=observable,
#                 analyzer="unknown",
#                 verdict=Verdict.UNKNOWN,
#                 confidence=0.0,
#                 error=str(e),
#             )
#             enrichments.append(failed_enrichment.model_dump())
#             processed_values.add(observable.value)

#     # Update state
#     investigation["enrichments"] = enrichments

#     # Remove processed observables from pending
#     new_pending = [
#         o for o in pending_observables
#         if (o.get("value") if isinstance(o, dict) else o.value) not in processed_values
#     ]

#     state["investigation"] = investigation
#     state["pending_observables"] = new_pending
#     state["current_enrichment_batch"] = []
#     state["last_updated"] = datetime.now().isoformat()

#     # If no more pending, move to analysis phase
#     if not new_pending:
#         state["current_phase"] = Phase.ANALYSIS.value

#     logger.info(
#         "cortex_worker_completed",
#         enriched=len(processed_values),
#         remaining=len(new_pending),
#     )

#     return state


# async def _enrich_observable(client: Any, vt_client: Any, observable: Observable, investigation: dict[str, Any]) -> EnrichmentResult | None:
#     """Enrich a single observable using appropriate Cortex analyzer.

#     Args:
#         client: Cortex MCP client.
#         observable: Observable to enrich.

#     Returns:
#         EnrichmentResult or None if enrichment fails.
#     """
#     analyzers = ANALYZER_MAP.get(observable.type, [])

#     if not analyzers:
#         logger.debug("no_analyzer_for_type", type=observable.type.value)
#         return EnrichmentResult(
#             observable=observable,
#             analyzer="none",
#             verdict=Verdict.UNKNOWN,
#             confidence=0.0,
#             details={"note": f"No analyzer available for type {observable.type.value}"},
#         )

#     # Try the first available analyzer for this type
#     tool_name, analyzer_name = analyzers[0]

#     # Prefer Cortex client; fall back to VirusTotal client for VT-capable tools
#     effective_client = client or vt_client
#     if effective_client is None:
#         # No client available
#         logger.warning("no_mcp_client_available", observable=observable.value)
#         return EnrichmentResult(
#             observable=observable,
#             analyzer=analyzer_name,
#             verdict=Verdict.UNKNOWN,
#             confidence=0.0,
#             details={"note": "No MCP client available for enrichment"},
#         )

#     # Build arguments based on tool and whether we're using VirusTotal fallback
#     # Use 15 retries (~60 seconds) to give analyzers time to complete
#     if tool_name == "analyze_ip_with_abuseipdb":
#         if effective_client is vt_client:
#             vt_tool = "vt_check_ip"
#             args = {"ip": observable.value}
#             tool_to_call = vt_tool
#             analyzer_name = "VirusTotal"
#         else:
#             args = {"ip": observable.value, "max_retries": 15}
#             tool_to_call = tool_name
#     elif tool_name in ("scan_url_with_virustotal", "analyze_url_with_urlscan_io"):
#         if effective_client is vt_client:
#             tool_to_call = "vt_check_url"
#             args = {"url": observable.value}
#             analyzer_name = "VirusTotal"
#         else:
#             args = {"url": observable.value, "max_retries": 15}
#             tool_to_call = tool_name
#     elif tool_name == "scan_hash_with_virustotal":
#         if effective_client is vt_client:
#             tool_to_call = "vt_check_hash"
#             args = {"hash": observable.value}
#             analyzer_name = "VirusTotal"
#         else:
#             args = {"hash": observable.value, "max_retries": 15}
#             tool_to_call = tool_name
#     elif tool_name == "analyze_with_abusefinder":
#         # Map observable type to AbuseFinder data_type
#         data_type_map = {
#             ObservableType.DOMAIN: "domain",
#             ObservableType.EMAIL: "mail",
#             ObservableType.FQDN: "fqdn",
#             ObservableType.IP: "ip",
#             ObservableType.URL: "url",
#         }
#         args = {
#             "data": observable.value,
#             "data_type": data_type_map.get(observable.type, "domain"),
#             "max_retries": 15,
#         }
#         tool_to_call = tool_name
#     else:
#         args = {"data": observable.value, "max_retries": 15}
#         tool_to_call = tool_name

#     # Investigation-level enrichment cache (dedup across phases)
#     # Keyed by tool name + normalized lookup value (hash/ip/domain/url)
#     cache = investigation.setdefault("enrichment_cache", {})
#     cache_key = None
#     normalized_lookup = None
#     if tool_to_call in ("vt_check_hash", "vt_check_ip", "vt_check_domain", "vt_check_url"):
#         if tool_to_call == "vt_check_hash":
#             normalized_lookup = args.get("hash")
#         elif tool_to_call == "vt_check_ip":
#             normalized_lookup = args.get("ip")
#         elif tool_to_call == "vt_check_domain":
#             normalized_lookup = args.get("domain")
#         elif tool_to_call == "vt_check_url":
#             normalized_lookup = args.get("url")

#         if normalized_lookup:
#             cache_key = f"{tool_to_call}:{normalized_lookup}"
#             if cache_key in cache:
#                 logger.info("virustotal_cache_hit", key=cache_key)
#                 cached = cache[cache_key]
#                 result = cached
#                 # Parse the result
#                 verdict, confidence, details = _parse_enrichment_result(result, tool_name)
#                 return EnrichmentResult(
#                     observable=observable,
#                     analyzer=analyzer_name,
#                     verdict=verdict,
#                     confidence=confidence,
#                     details=details,
#                 )

#     try:
#         result = await effective_client.call_tool(tool_to_call, args)

#         # Cache successful VirusTotal lookups to avoid duplicate API calls
#         try:
#             rl = (result or "").lower()
#             if cache_key and "rate limit" not in rl and "http 429" not in rl:
#                 cache[cache_key] = result
#                 logger.info("virustotal_cache_store", key=cache_key)
#         except Exception:
#             # Ignore cache-store errors
#             pass

#         # Parse the result
#         verdict, confidence, details = _parse_enrichment_result(result, tool_name)

#         return EnrichmentResult(
#             observable=observable,
#             analyzer=analyzer_name,
#             verdict=verdict,
#             confidence=confidence,
#             details=details,
#         )

#     except Exception as e:
#         logger.error(
#             "analyzer_failed",
#             tool=tool_name,
#             observable=observable.value[:50],
#             error=str(e),
#         )
#         raise


# def _parse_enrichment_result(
#     result: str, tool_name: str
# ) -> tuple[Verdict, float, dict[str, Any]]:
#     """Parse enrichment result and determine verdict.

#     Args:
#         result: Raw result from Cortex tool.
#         tool_name: Name of the tool used.

#     Returns:
#         Tuple of (verdict, confidence, details).
#     """
#     details: dict[str, Any] = {"raw_result": result[:1000] if result else ""}

#     # Try to parse as JSON
#     try:
#         if result and result.strip().startswith("{"):
#             parsed = json.loads(result)
#             details = parsed
#     except json.JSONDecodeError:
#         pass

#     # Determine verdict based on tool and result
#     verdict = Verdict.UNKNOWN
#     confidence = 0.5

#     result_lower = result.lower() if result else ""

#     # AbuseIPDB patterns
#     if tool_name == "analyze_ip_with_abuseipdb":
#         if "abuse confidence score" in result_lower:
#             # Extract score
#             import re
#             score_match = re.search(r"abuse confidence score[:\s]*(\d+)", result_lower)
#             if score_match:
#                 score = int(score_match.group(1))
#                 if score >= 80:
#                     verdict = Verdict.MALICIOUS
#                     confidence = score / 100
#                 elif score >= 30:
#                     verdict = Verdict.SUSPICIOUS
#                     confidence = score / 100
#                 else:
#                     verdict = Verdict.BENIGN
#                     confidence = 1 - (score / 100)

#     # VirusTotal patterns
#     elif "virustotal" in tool_name.lower():
#         if "malicious" in result_lower:
#             # Look for detection ratio
#             import re
#             ratio_match = re.search(r"(\d+)/(\d+)", result_lower)
#             if ratio_match:
#                 detections = int(ratio_match.group(1))
#                 total = int(ratio_match.group(2))
#                 if total > 0:
#                     ratio = detections / total
#                     if ratio >= 0.3:
#                         verdict = Verdict.MALICIOUS
#                         confidence = min(0.95, 0.5 + ratio)
#                     elif ratio >= 0.1:
#                         verdict = Verdict.SUSPICIOUS
#                         confidence = 0.5 + ratio
#                     else:
#                         verdict = Verdict.BENIGN
#                         confidence = 1 - ratio
#             else:
#                 # Just the word "malicious" without ratio
#                 verdict = Verdict.SUSPICIOUS
#                 confidence = 0.6

#         elif "clean" in result_lower or "harmless" in result_lower:
#             verdict = Verdict.BENIGN
#             confidence = 0.8

#     # Urlscan.io patterns
#     elif "urlscan" in tool_name.lower():
#         if "malicious" in result_lower or "phishing" in result_lower:
#             verdict = Verdict.MALICIOUS
#             confidence = 0.8
#         elif "suspicious" in result_lower:
#             verdict = Verdict.SUSPICIOUS
#             confidence = 0.6
#         elif "safe" in result_lower or "benign" in result_lower:
#             verdict = Verdict.BENIGN
#             confidence = 0.7

#     # AbuseFinder patterns
#     elif "abusefinder" in tool_name.lower():
#         if "abuse" in result_lower and "found" in result_lower:
#             verdict = Verdict.SUSPICIOUS
#             confidence = 0.6
#         elif "no abuse" in result_lower:
#             verdict = Verdict.BENIGN
#             confidence = 0.7

#     # Generic fallback patterns
#     if verdict == Verdict.UNKNOWN:
#         if any(word in result_lower for word in ["malware", "threat", "attack", "dangerous"]):
#             verdict = Verdict.MALICIOUS
#             confidence = 0.7
#         elif any(word in result_lower for word in ["suspicious", "potentially", "risky"]):
#             verdict = Verdict.SUSPICIOUS
#             confidence = 0.5
#         elif any(word in result_lower for word in ["clean", "safe", "benign", "legitimate"]):
#             verdict = Verdict.BENIGN
#             confidence = 0.6

#     return verdict, confidence, details
