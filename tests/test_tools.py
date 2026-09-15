"""Unit tests for the deterministic tool layer -- none of this should require an LLM to verify.

    pytest -q
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from tools.audit_tools import (  # noqa: E402
    _load,
    check_policy,
    classify_failures,
    get_policy_summary,
    group_by_actor,
    list_failures,
)
from tools.policy import evaluate_policy  # noqa: E402


@pytest.fixture(scope="module")
def sample_log(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("data") / "logs.jsonl"
    subprocess.run(
        [sys.executable, str(REPO / "data" / "generate_sample_logs.py"), "--n", "300", "--out", str(out)],
        check=True,
        capture_output=True,
    )
    return out


def test_generator_is_deterministic(tmp_path: Path) -> None:
    """The same seed must produce the same data, otherwise the numbers in a report are not reproducible."""
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    for target in (a, b):
        subprocess.run(
            [sys.executable, str(REPO / "data" / "generate_sample_logs.py"),
             "--n", "50", "--seed", "7", "--out", str(target)],
            check=True, capture_output=True,
        )
    assert json.loads(a.read_text().splitlines()[0])["operation"] == json.loads(
        b.read_text().splitlines()[0]
    )["operation"]


def test_generator_contains_no_real_identifiers(tmp_path: Path) -> None:
    """Compliance guard: synthetic data must never contain a real account, host or home path.

    The patterns here are deliberately generic. A deny-list that names a real organisation or host
    would itself publish the very strings this repository promises never to ship -- including in
    its own guard rails.
    """
    out = tmp_path / "logs.jsonl"
    subprocess.run(
        [sys.executable, str(REPO / "data" / "generate_sample_logs.py"), "--n", "200", "--out", str(out)],
        check=True, capture_output=True,
    )
    text = out.read_text()
    for pattern, label in (
        (r"@", "an email-like token"),
        (r"/Users/|/home/", "an absolute home path"),
        (r"\.(?:com|net|org|local|internal)\b", "a hostname"),
    ):
        assert not re.search(pattern, text), f"synthetic data leaked {label} (/{pattern}/)"


def test_every_actor_comes_from_the_generator_roster(tmp_path: Path) -> None:
    """The only actor names that may appear are the ones the generator itself declares."""
    gen = _load_generator()
    out = tmp_path / "logs.jsonl"
    subprocess.run(
        [sys.executable, str(REPO / "data" / "generate_sample_logs.py"), "--n", "200", "--out", str(out)],
        check=True, capture_output=True,
    )
    actors = {json.loads(line)["actor"] for line in out.read_text().splitlines() if line.strip()}
    assert actors <= set(gen.USERS), f"unexpected actor names: {actors - set(gen.USERS)}"


def test_every_path_stays_inside_the_synthetic_root(tmp_path: Path) -> None:
    """Every generated path must live under the invented /studio/ tree, never a real mount."""
    out = tmp_path / "logs.jsonl"
    subprocess.run(
        [sys.executable, str(REPO / "data" / "generate_sample_logs.py"), "--n", "200", "--out", str(out)],
        check=True, capture_output=True,
    )
    paths = {json.loads(line)["path"] for line in out.read_text().splitlines() if line.strip()}
    assert paths and all(p.startswith("/studio/") for p in paths), "a generated path escaped the synthetic root"


def test_client_ips_are_private_ranges_only(tmp_path: Path) -> None:
    """Client addresses must stay in RFC1918 space; a public address would suggest copied real data."""
    out = tmp_path / "logs.jsonl"
    subprocess.run(
        [sys.executable, str(REPO / "data" / "generate_sample_logs.py"), "--n", "200", "--out", str(out)],
        check=True, capture_output=True,
    )
    ips = {json.loads(line)["client_ip"] for line in out.read_text().splitlines() if line.strip()}
    assert all(ip.startswith("10.") for ip in ips), f"non-private address generated: {ips}"


def _load_generator():
    import importlib.util

    spec = importlib.util.spec_from_file_location("gen", REPO / "data" / "generate_sample_logs.py")
    assert spec and spec.loader
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    return gen


def test_summarize_counts_match_raw(sample_log: Path) -> None:
    rows = _load(str(sample_log))
    raw_fails = sum(1 for r in rows if not r.get("success"))
    summary = list_failures.invoke({"log_path": str(sample_log)})
    assert f"{raw_fails} failed events in total" in summary


def test_group_by_actor_totals_are_consistent(sample_log: Path) -> None:
    rows = _load(str(sample_log))
    fails = [r for r in rows if not r.get("success")]
    expected = Counter(r["actor"] for r in fails).most_common(1)[0][0]
    out = group_by_actor.invoke({"log_path": str(sample_log), "only_failures": True})
    assert expected in out.splitlines()[0], "the actor with the most failures should be listed first"


@pytest.mark.parametrize(
    ("zone", "op", "role", "is_owner", "expect"),
    [
        ("product", "modify", "artist", True, "DENY"),          # delivery zone is immutable, even for the owner
        ("product", "modify", "pipeline_admin", False, "ALLOW"),  # but an admin role may
        ("work", "modify", "artist", True, "ALLOW"),            # you may write your own work area
        ("work", "modify", "artist", False, "DENY"),            # but not somebody else's
        ("user_profile", "delete", "artist", True, "ALLOW"),
        ("work", "mkdir", "artist", False, "ALLOW"),            # self_bootstrap
        ("nonsense", "modify", "pipeline_admin", True, "UNKNOWN_ZONE"),
    ],
)
def test_check_policy_matrix(zone: str, op: str, role: str, is_owner: bool, expect: str) -> None:
    result = check_policy.invoke(
        {"zone": zone, "operation": op, "role": role, "is_owner": is_owner}
    )
    assert result.startswith(expect), f"{zone}/{op} expected {expect}, got {result}"


def test_admin_is_decided_by_role_membership() -> None:
    """A role only counts as admin if the policy lists it -- not by name resemblance."""
    policy = json.loads((REPO / "data" / "policy_rules.json").read_text())
    for role in policy["admin_roles"]:
        allowed, _ = evaluate_policy("product", "modify", role, False, policy)
        assert allowed, f"{role} is listed admin but was denied product/modify"
    # A plausible-sounding but unlisted role must NOT get admin powers.
    allowed, _ = evaluate_policy("product", "modify", "admin_assistant", False, policy)
    assert not allowed, "an unlisted role must not be treated as admin"


def test_events_carry_role_and_ownership(sample_log: Path) -> None:
    """Grounding fields must be present on every event so verdicts need no guessing."""
    rows = _load(str(sample_log))
    gen = _load_generator()
    for r in rows:
        assert r["actor_role"] == gen.ROLE_BY_USER[r["actor"]], "actor_role must match the roster"
        assert isinstance(r["is_owner"], bool)


def test_generated_data_is_policy_consistent(sample_log: Path) -> None:
    """A successful event may never be one the policy would have denied.

    This is the whole point of sharing tools/policy.py: outcomes in the data and the analyst's
    later verdicts come from one function, so they cannot contradict each other.
    """
    for r in _load(str(sample_log)):
        allowed, reason = evaluate_policy(r["zone"], r["operation"], r["actor_role"], r["is_owner"])
        if r["success"]:
            assert allowed, f"a denied action was recorded as success: {r} ({reason})"


def test_classify_failures_matches_independent_count(sample_log: Path) -> None:
    """classify_failures' violation total must equal an independent policy re-evaluation."""
    rows = [r for r in _load(str(sample_log)) if not r["success"]]
    expected_violations = sum(
        1
        for r in rows
        if not evaluate_policy(r["zone"], r["operation"], r["actor_role"], r["is_owner"])[0]
    )
    out = classify_failures.invoke({"log_path": str(sample_log)})
    m = re.search(r"violations:\s*(\d+)", out)
    assert m and int(m.group(1)) == expected_violations, out


def test_policy_summary_mentions_every_zone() -> None:
    policy = json.loads((REPO / "data" / "policy_rules.json").read_text())
    summary = get_policy_summary.invoke({})
    for zone in policy["zones"]:
        assert zone in summary
