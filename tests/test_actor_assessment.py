"""Tests for the TypeSafe per-actor assessment -- no API key or network needed.

The TypeSafe client is replaced by a fake returning canned typed answers, so these pin down what
*our* code owns: which state the model sees, how answers map to an action, ordering, and the
service's status codes. Model quality is a separate question, checked live, not in CI.

    pytest -q
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from typesafe_sdk import TypeSafeAPIConnectionError

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import server  # noqa: E402
from tools import actor_assessment as aa  # noqa: E402


def _event(ts: str, actor: str, *, success: bool, own: bool = True, op: str = "create") -> dict:
    owner = actor if own else "someone.else"
    return {
        "ts": ts, "operation": op, "actor": actor, "actor_role": "artist", "zone": "work",
        "path": f"/studio/film/devrnd/sequence/SHOWA/work/{owner}/scene",
        "is_owner": own, "success": success, "reason": None if success else "denied",
    }


@pytest.fixture
def log(tmp_path: Path) -> Path:
    rows = (
        # noisy: 3 cross-user violations + 1 own-dir permission error, of 5 events
        [_event(f"2026-01-01T00:0{i}:00Z", "noisy", success=False, own=False) for i in range(3)]
        + [_event("2026-01-01T00:05:00Z", "noisy", success=False, own=True)]
        + [_event("2026-01-01T00:06:00Z", "noisy", success=True)]
        # quiet: 1 permission error, of 4 events
        + [_event("2026-01-01T01:00:00Z", "quiet", success=False)]
        + [_event(f"2026-01-01T01:0{i}:00Z", "quiet", success=True) for i in range(1, 4)]
        # clean: never fails, so is never assessed
        + [_event("2026-01-01T02:00:00Z", "clean", success=True)]
    )
    p = tmp_path / "log.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return p


class FakeClient:
    """Stands in for TypeSafeClient: canned answers per actor, and records every state sent."""

    def __init__(self, by_actor: dict[str, tuple[str, float, float, float]]) -> None:
        self.by_actor = by_actor  # actor -> (choice, choice_conf, score, score_conf)
        self.states: list[dict] = []

    def system_one(self, *, state: dict, questions: dict) -> SimpleNamespace:
        assert set(questions) == {"explanation", "concern"}
        self.states.append(state)
        choice, c_conf, score, s_conf = self.by_actor[state["actor"]]
        return SimpleNamespace(answers={
            "explanation": SimpleNamespace(choice=choice, confidence=c_conf,
                                           probabilities={choice: 0.9}),
            "concern": SimpleNamespace(score=score, confidence=s_conf),
        })


# --- state: the model sees decided facts, not raw guesses -------------------------------------

def test_state_carries_policy_verdicts_and_counts(log: Path) -> None:
    states = {s["actor"]: s for s in aa.build_actor_states(aa._load(str(log)), top_n=5)}
    assert set(states) == {"noisy", "quiet"}, "actors without failures must not be assessed"
    noisy = states["noisy"]
    assert (noisy["violations"], noisy["permission_errors"]) == (3, 1)
    assert noisy["violation_rate"] == round(3 / 5, 3)
    assert {e["verdict"] for e in noisy["failed_events"]} == {"VIOLATION", "PERMISSION_ERROR"}


def test_state_includes_an_org_baseline(log: Path) -> None:
    baseline = aa.build_actor_states(aa._load(str(log)), top_n=1)[0]["org_baseline"]
    assert baseline["actors"] == 3
    assert baseline["max_violation_rate"] == round(3 / 5, 3)
    assert baseline["median_violation_rate"] == 0.0


def test_evidence_is_capped_per_actor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(aa, "MAX_EVENTS_PER_ACTOR", 2)
    rows = [_event(f"2026-01-01T00:0{i}:00Z", "x", success=False, own=False) for i in range(5)]
    state = aa.build_actor_states(rows)[0]
    assert state["failed_events_shown"] == 2 and state["violations"] == 5, "counts use every event"
    assert state["failed_events"][0]["ts"] == "2026-01-01T00:04:00Z", "newest evidence first"


# --- action policy is code-owned ---------------------------------------------------------------

@pytest.mark.parametrize("c_conf,score,s_conf,expect", [
    (0.9, 2.8, 0.9, "escalate"),
    (0.9, 2.0, 0.9, "follow_up"),
    (0.9, 0.4, 0.9, "note"),
    (0.3, 2.9, 0.9, "human_review"),   # a split explanation is not grounds to escalate
    (0.9, 2.9, 0.4, "human_review"),
])
def test_decide_action(c_conf: float, score: float, s_conf: float, expect: str) -> None:
    assert aa.decide_action({"confidence": c_conf}, {"score": score, "confidence": s_conf}) == expect


def test_results_are_ordered_by_concern(log: Path) -> None:
    fake = FakeClient({"noisy": ("probing", 0.9, 2.7, 0.8), "quiet": ("honest_mistake", 0.9, 0.3, 0.9)})
    results = aa.assess_actors(str(log), client=fake)
    assert [r["actor"] for r in results] == ["noisy", "quiet"]
    assert [r["action"] for r in results] == ["escalate", "note"]
    assert results[0]["concern"]["level"] == aa.CONCERN_LEVELS[3]
    assert len(fake.states) == 2


def test_no_key_raises_unavailable(log: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(aa.API_KEY_ENV, raising=False)
    with pytest.raises(aa.AssessmentUnavailable):
        aa.assess_actors(str(log))


# --- service contract ---------------------------------------------------------------------------

@pytest.fixture
def client() -> TestClient:
    return TestClient(server.app)


def test_route_returns_assessments(client: TestClient, log: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeClient({"noisy": ("probing", 0.9, 2.7, 0.8), "quiet": ("honest_mistake", 0.9, 0.3, 0.9)})
    real = aa.assess_actors
    monkeypatch.setattr(aa, "assess_actors", lambda p, n: real(p, n, client=fake))
    r = client.get("/actors/assessment", params={"logs": str(log)})
    assert r.status_code == 200, r.text
    assert r.json()["actors"][0]["actor"] == "noisy"


def test_route_503s_without_a_key(client: TestClient, log: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(aa.API_KEY_ENV, raising=False)
    r = client.get("/actors/assessment", params={"logs": str(log)})
    assert r.status_code == 503, r.text


def test_route_502s_when_typesafe_fails(client: TestClient, log: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(_p: str, _n: int):
        raise TypeSafeAPIConnectionError("connection refused")

    monkeypatch.setattr(aa, "assess_actors", _boom)
    r = client.get("/actors/assessment", params={"logs": str(log)})
    assert r.status_code == 502, r.text


def test_route_400s_on_a_bad_log_before_calling_typesafe(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = []
    monkeypatch.setattr(aa, "assess_actors", lambda *a: called.append(a))
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{ not json }\n")
    r = client.get("/actors/assessment", params={"logs": str(bad)})
    assert r.status_code == 400 and not called


def test_route_rejects_out_of_range_top_n(client: TestClient, log: Path) -> None:
    r = client.get("/actors/assessment", params={"logs": str(log), "top_n": 0})
    assert r.status_code == 400
