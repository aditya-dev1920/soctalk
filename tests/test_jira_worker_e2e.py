import asyncio
import json

import pytest

from soctalk.workers.jira import jira_worker_node
from soctalk.models.enums import Phase


class MockMCPClient:
    def __init__(self, response=None):
        self.last_call = None
        self.response = response or {"issue_key": "SEC-123"}

    async def call_tool(self, name: str, args: dict | None = None):
        self.last_call = (name, args)
        # Simulate async network latency
        await asyncio.sleep(0)
        return self.response


@pytest.mark.asyncio
async def test_jira_worker_creates_ticket_and_records_key(monkeypatch, tmp_path):
    # Prepare mock clients
    mock_jira = MockMCPClient(response={"issue_key": "SEC-123"})
    mock_thehive = MockMCPClient(response={"_id": "case-1"})

    # Monkeypatch binding accessors imported in jira module
    import soctalk.workers.jira as jira_mod

    monkeypatch.setattr(jira_mod, "get_jira_client", lambda: mock_jira)
    monkeypatch.setattr(jira_mod, "get_thehive_client", lambda: mock_thehive)

    # Build minimal state representing end of Phase 3, entering Phase 4 (escalation)
    state = {
        "current_phase": Phase.ESCALATION.value,
        "alert": {
            "threat_name": "TestThreat",
            "host": "GG-LPT-TEST01",
            "severity": "High",
            "timestamp": "2026-08-31T12:00:00Z",
            "sha256": "a" * 64,
            "file_path": "C:\\Program Files\\Test\\test.exe",
        },
        "investigation": {"id": "inv-1", "severity": "High"},
        "verdict": {"sop_verdict": "True Positive – Malicious", "recommendation": "## 1\nThreat\n## 2\nImpact\n## 3\nRemediation"},
        "findings": ["Sample finding 1", "Sample finding 2"],
    }

    new_state = await jira_worker_node(state)

    # Assert Jira call occurred
    assert mock_jira.last_call is not None
    name, args = mock_jira.last_call
    assert name == "jira_create_ticket"
    assert "summary" in args
    assert "description" in args

    # Assert issue key recorded
    inv = new_state.get("investigation", {})
    assert inv.get("jira_issue_key") == "SEC-123"
    # Current phase should be closed after successful run
    assert new_state.get("current_phase") == Phase.CLOSED.value
