"""Tests for Jira payload validator and normalizer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soctalk.workers.jira_schema import (
    normalize_jira_payload,
    strict_validate_jira_payload,
    validate_jira_payload,
)


def test_validate_and_normalize_minimal_payload():
    payload = {
        "summary": "Suspicious binary on host-1",
        "threat_title": "Suspicious Binary on host-1",
        "threat_description": "Hi Team\n\nDetails...",
        "impact_for_you": "**File Analysis**\n- suspicious",
        "remediation_steps": "Isolate host, Quarantine file",
        "customfield_10044": "10030",
        "customfield_10220": "10327",
        "project": "SEC",
        "issue_type": "Incident",
    }

    is_valid, errors = validate_jira_payload(payload)
    assert is_valid, f"Validation errors: {errors}"
    assert not errors

    normalized = normalize_jira_payload(payload)
    assert isinstance(normalized.get("remediation_steps"), list)
    assert len(normalized["remediation_steps"]) == 2
    assert normalized.get("customfield_10044") == 10030
    assert normalized.get("customfield_10220") == 10327


def test_alias_normalization_and_coercion():
    alias_payload = {
        "summary": "NopalCyber SOC Alert | Suspicious PowerShell on HOST1 | High",
        "threat_title": "NopalCyber SOC Alert | Suspicious PowerShell on HOST1 | High",
        "threat_description": "Hi Team\n\n#### Threat Overview\n...",
        "impact": "**File Analysis**\n- item",
        "remediation": "* Contain host\n* Revoke credential",
        "severity": "10029",
        "analyst_verdict": 10327,
    }

    normalized = normalize_jira_payload(alias_payload)
    assert normalized["customfield_10044"] == 10029
    assert normalized["customfield_10220"] == 10327
    assert normalized["project"] == "SEC"
    assert normalized["issue_type"] == "Incident"
    assert normalized["impact_for_you"] == "**File Analysis**\n- item"
    assert len(normalized["remediation_steps"]) == 2


def test_strict_validation_accepts_valid_example():
    template_path = Path(__file__).resolve().parents[1] / "docs" / "jira_template.json"
    if not template_path.exists():
        template_path = Path("docs/jira_template.json")

    with open(template_path, "r", encoding="utf-8") as f:
        tmpl = json.load(f)

    payload = {
        "summary": "NopalCyber SOC Alert | SuspiciousBinary Detected on host-1 | High",
        "threat_title": "NopalCyber SOC Alert | SuspiciousBinary Detected on host-1 | High",
        "threat_description": (
            "Hi Team\n\n"
            "#### Threat Overview\n"
            "| Field | Value |\n"
            "| Threat Name | SuspiciousBinary |\n"
            "#### Threat Details\n"
            "| Field | Value |\n"
            "| Threat ID | 12345 |"
        ),
        "impact_for_you": (
            "**File Analysis**\n- item\n"
            "**Process & Command-Line Analysis**\n- item\n"
            "**Storyline Analysis**\n- item\n"
            "**Persistence & Lateral Movement Analysis**\n- item\n"
            "**Network Analysis**\n- item\n"
            "**30-Day Estate Sweep Results**\n- 0 hits"
        ),
        "remediation_steps": ["Isolate host", "Quarantine file"],
        "customfield_10044": 10029,
        "customfield_10220": 10327,
        "project": "SEC",
        "issue_type": "Incident",
    }

    ok, errs = strict_validate_jira_payload(payload, tmpl)
    assert ok, f"Strict validation failed: {errs}"