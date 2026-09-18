"""Route-level tests for the FastAPI service -- no model endpoint required.

The crew is stubbed where a route would reach for an LLM, so everything here stays deterministic
and runnable in CI. What these tests guard is the service *contract*: which status code a caller
gets back. Bad input must read as 4xx (the caller can fix it), a dead model endpoint as 502, and
nothing may leak out as a 500.

    pytest -q
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import server  # noqa: E402
from tools.audit_tools import _load  # noqa: E402


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(server.app)


@pytest.fixture(scope="module")
def sample_log(tmp_path_factory: pytest.TempPathFactory) -> Path:
    import subprocess

    out = tmp_path_factory.mktemp("data") / "logs.jsonl"
    subprocess.run(
        [sys.executable, str(REPO / "data" / "generate_sample_logs.py"),
         "--n", "120", "--out", str(out)],
        check=True, capture_output=True,
    )
    return out


def _write(path: Path, rows: list[dict]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


def _event(ts: str, **over) -> dict:
    row = {
        "ts": ts, "operation": "create", "actor": "a.chen", "actor_role": "artist",
        "zone": "work", "path": "/studio/film/devrnd/sequence/SHOWA/work/a.chen/scene",
        "is_owner": True, "success": True, "reason": None,
    }
    row.update(over)
    return row


# --- /health, /policies -----------------------------------------------------------------------

def test_health_reports_the_configured_model(client: TestClient) -> None:
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["model"] and body["base_url"], "health must say which endpoint it would call"


def test_policies_returns_the_policy_the_tools_use(client: TestClient) -> None:
    """The route must serve the same file the policy engine reads, not a copy that can drift."""
    body = client.get("/policies").json()
    on_disk = json.loads((REPO / "data" / "policy_rules.json").read_text())
    assert body == on_disk


# --- /events/summary --------------------------------------------------------------------------

def test_events_summary_matches_a_raw_recount(client: TestClient, sample_log: Path) -> None:
    body = client.get("/events/summary", params={"logs": str(sample_log)}).json()
    rows = _load(str(sample_log))
    assert body["events"] == len(rows)
    assert body["failures"] == sum(1 for r in rows if not r["success"])


def test_events_summary_404s_on_a_missing_log(client: TestClient, tmp_path: Path) -> None:
    r = client.get("/events/summary", params={"logs": str(tmp_path / "nope.jsonl")})
    assert r.status_code == 404


def test_events_summary_400s_on_malformed_json(client: TestClient, tmp_path: Path) -> None:
    """A broken line is the caller's problem (4xx), and the message must name the line."""
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps(_event("2026-01-01T00:00:00Z")) + "\n{ not json }\n")
    r = client.get("/events/summary", params={"logs": str(bad)})
    assert r.status_code == 400, r.text
    assert "line 2" in r.json()["detail"]


def test_events_summary_400s_on_a_missing_required_field(client: TestClient, tmp_path: Path) -> None:
    row = _event("2026-01-01T00:00:00Z")
    del row["zone"]
    r = client.get("/events/summary", params={"logs": str(_write(tmp_path / "m.jsonl", [row]))})
    assert r.status_code == 400, r.text
    assert "zone" in r.json()["detail"]


def test_events_summary_handles_an_empty_log(client: TestClient, tmp_path: Path) -> None:
    """An empty log is valid input -- zero events, not a crash."""
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    r = client.get("/events/summary", params={"logs": str(empty)})
    assert r.status_code == 200, r.text
    assert r.json()["events"] == 0 and r.json()["window"] == []


def test_events_summary_window_is_ordered_for_unsorted_input(client: TestClient, tmp_path: Path) -> None:
    """Audit logs are not guaranteed sorted; the reported window must still run forwards."""
    log = _write(tmp_path / "unsorted.jsonl", [
        _event("2026-01-02T00:00:00Z"),
        _event("2026-01-01T00:00:00Z"),
        _event("2026-01-03T00:00:00Z"),
    ])
    window = client.get("/events/summary", params={"logs": str(log)}).json()["window"]
    assert window == ["2026-01-01T00:00:00Z", "2026-01-03T00:00:00Z"], window


# --- /triage ----------------------------------------------------------------------------------

class _StubCrew:
    """Stands in for a CrewAI crew so the route can be exercised without a model endpoint."""

    def __init__(self, report: str = "# stub report") -> None:
        self.report = report
        self.kicked = 0

    def kickoff(self) -> str:
        self.kicked += 1
        return self.report


def test_triage_returns_report_and_deterministic_stats(
    client: TestClient, sample_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = _StubCrew()
    monkeypatch.setattr(server, "build_crew", lambda _p: stub)
    r = client.post("/triage", json={"logs": str(sample_log), "write_report": False})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["report"] == "# stub report"
    assert body["report_path"] is None
    assert body["stats"]["events"] == len(_load(str(sample_log)))


def test_triage_writes_the_report_when_asked(
    client: TestClient, sample_log: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(server, "build_crew", lambda _p: _StubCrew("# written"))
    monkeypatch.setattr(server, "REPO", tmp_path)  # never clobber the repo's own report.md
    r = client.post("/triage", json={"logs": str(sample_log), "write_report": True})
    assert r.status_code == 200, r.text
    assert (tmp_path / "report.md").read_text() == "# written"


def test_triage_404s_on_a_missing_log(client: TestClient, tmp_path: Path) -> None:
    r = client.post("/triage", json={"logs": str(tmp_path / "nope.jsonl")})
    assert r.status_code == 404


def test_triage_rejects_a_bad_log_before_calling_the_model(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validation comes first: a malformed log must 400 without spending a model call."""
    stub = _StubCrew()
    monkeypatch.setattr(server, "build_crew", lambda _p: stub)
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{ not json }\n")
    r = client.post("/triage", json={"logs": str(bad), "write_report": False})
    assert r.status_code == 400, r.text
    assert stub.kicked == 0, "the crew ran despite the log being unreadable"


def test_triage_502s_when_the_model_endpoint_fails(
    client: TestClient, sample_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dead endpoint is an upstream failure, kept distinct from bad input and from our own bugs."""
    def _boom(_p: str):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(server, "build_crew", _boom)
    r = client.post("/triage", json={"logs": str(sample_log), "write_report": False})
    assert r.status_code == 502, r.text
    assert "connection refused" in r.json()["detail"]
