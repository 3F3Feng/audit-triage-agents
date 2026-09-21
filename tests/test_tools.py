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
    AuditLogError,
    _load,
    check_policy,
    classify_failures,
    get_policy_summary,
    group_by_actor,
    list_failures,
    summarize_events,
)
from tools.policy import evaluate_policy, owner_of_path  # noqa: E402


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


def _event(ts: str, **over) -> dict:
    row = {
        "ts": ts, "operation": "create", "actor": "a.chen", "actor_role": "artist",
        "zone": "work", "path": "/studio/film/devrnd/sequence/SHOWA/work/a.chen/scene",
        "is_owner": True, "success": True, "reason": None,
    }
    row.update(over)
    return row


def _write_log(path: Path, rows: list[dict]) -> str:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return str(path)


def test_summarize_events_totals_match_raw(sample_log: Path) -> None:
    rows = _load(str(sample_log))
    out = summarize_events.invoke({"log_path": str(sample_log)})
    assert f"total events: {len(rows)}" in out
    assert f"failures: {sum(1 for r in rows if not r['success'])} " in out


def test_summarize_events_time_range_is_ordered(tmp_path: Path) -> None:
    """Out-of-order input must not produce a window that runs backwards (see list_failures,
    which has always sorted -- the two must agree)."""
    log = _write_log(tmp_path / "unsorted.jsonl", [
        _event("2026-01-02T00:00:00Z"),
        _event("2026-01-01T00:00:00Z"),
        _event("2026-01-03T00:00:00Z"),
    ])
    out = summarize_events.invoke({"log_path": log})
    assert "time range: 2026-01-01T00:00:00Z -> 2026-01-03T00:00:00Z" in out


@pytest.mark.parametrize(
    "tool",
    [summarize_events, list_failures, group_by_actor, classify_failures],
)
def test_tools_handle_an_empty_log(tool, tmp_path: Path) -> None:
    """Every log-reading tool must answer an empty log in words, not raise.

    summarize_events used to be the odd one out: it indexed rows[0] and raised IndexError while
    its siblings returned a message.
    """
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    out = tool.invoke({"log_path": str(empty)})
    assert isinstance(out, str) and out.strip(), f"{tool.name} returned nothing for an empty log"


def test_load_reports_the_line_of_malformed_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps(_event("2026-01-01T00:00:00Z")) + "\n{ not json }\n")
    with pytest.raises(AuditLogError, match="line 2"):
        _load(str(bad))


def test_load_rejects_a_row_missing_a_required_field(tmp_path: Path) -> None:
    """Tools index these fields directly, so a row without them must fail loudly at load time."""
    row = _event("2026-01-01T00:00:00Z")
    del row["operation"]
    with pytest.raises(AuditLogError, match="operation"):
        _load(_write_log(tmp_path / "missing.jsonl", [row]))


def test_load_rejects_a_non_object_row(tmp_path: Path) -> None:
    bad = tmp_path / "scalar.jsonl"
    bad.write_text("[1, 2, 3]\n")
    with pytest.raises(AuditLogError, match="JSON object"):
        _load(str(bad))


def test_load_still_raises_file_not_found(tmp_path: Path) -> None:
    """A missing file stays FileNotFoundError -- the service maps that to 404, not 400."""
    with pytest.raises(FileNotFoundError):
        _load(str(tmp_path / "nope.jsonl"))


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
    assert expected in out.splitlines()[1], "the actor with the most failures should be listed first"


def test_group_by_actor_total_counts_every_event(tmp_path: Path) -> None:
    """only_failures must not shrink the denominator: 1 failure out of 3 events reads "1 / 3"."""
    base = {"operation": "create", "actor_role": "artist", "zone": "work",
            "path": "/studio/film/devrnd/sequence/SHOWA/work/a/scene", "is_owner": True}
    rows = [
        {**base, "ts": "2026-01-01T00:00:00Z", "actor": "a", "success": False},
        {**base, "ts": "2026-01-01T00:01:00Z", "actor": "a", "success": True},
        {**base, "ts": "2026-01-01T00:02:00Z", "actor": "a", "success": True, "zone": "product"},
        {**base, "ts": "2026-01-01T00:03:00Z", "actor": "clean", "success": True},
    ]
    log = tmp_path / "log.jsonl"
    log.write_text("".join(json.dumps(r) + "\n" for r in rows))

    out = group_by_actor.invoke({"log_path": str(log), "only_failures": True})
    assert "failures   1 / total   3 (33.3%)" in out
    assert "clean" not in out, "actors that never failed are dropped when only_failures"
    assert "product" not in out, "the zone breakdown covers failed events only"

    everything = group_by_actor.invoke({"log_path": str(log), "only_failures": False})
    assert "clean" in everything and "'product': 1" in everything


@pytest.mark.parametrize(
    ("zone", "op", "role", "is_owner", "expect"),
    [
        ("product", "modify", "artist", True, "DENY"),          # delivery zone is immutable, even for the owner
        ("product", "modify", "pipeline_admin", False, "ALLOW"),  # but an admin role may
        ("work", "modify", "artist", True, "ALLOW"),            # you may write your own work area
        ("work", "modify", "artist", False, "DENY"),            # but not somebody else's
        ("user_profile", "delete", "artist", True, "ALLOW"),
        ("nonsense", "modify", "pipeline_admin", True, "UNKNOWN_ZONE"),
    ],
)
def test_check_policy_matrix(zone: str, op: str, role: str, is_owner: bool, expect: str) -> None:
    result = check_policy.invoke(
        {"zone": zone, "operation": op, "role": role, "is_owner": is_owner}
    )
    assert result.startswith(expect), f"{zone}/{op} expected {expect}, got {result}"


@pytest.mark.parametrize(
    ("actor", "path", "expect"),
    [
        # self_bootstrap lets a user create their *own* work directory before they own it ...
        ("a.chen", "/studio/film/devrnd/sequence/SHOWA/work/a.chen/scene", "ALLOW"),
        # ... and that is the whole of the grant: another user's directory is still off limits.
        ("a.chen", "/studio/film/devrnd/sequence/SHOWA/work/j.goran/scene", "DENY"),
    ],
)
def test_self_bootstrap_only_covers_ones_own_directory(actor: str, path: str, expect: str) -> None:
    """work/mkdir is decided by who the target path belongs to, not merely by the rule existing.

    Both cases carry is_owner=False -- that is what makes them bootstrap cases at all. The
    difference is the owner segment of the path, so a grant meant for setting up your own area
    cannot be read as permission to write into somebody else's.
    """
    result = check_policy.invoke(
        {"zone": "work", "operation": "mkdir", "role": "artist", "is_owner": False,
         "actor": actor, "path": path}
    )
    assert result.startswith(expect), f"work/mkdir on {path} expected {expect}, got {result}"


def test_self_bootstrap_denies_when_the_target_is_unknown() -> None:
    """With no caller/path to check against, the rule must deny rather than assume the best."""
    result = check_policy.invoke(
        {"zone": "work", "operation": "mkdir", "role": "contractor", "is_owner": False}
    )
    assert result.startswith("DENY"), result


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
        allowed, reason = evaluate_policy(
            r["zone"], r["operation"], r["actor_role"], r["is_owner"],
            actor=r["actor"], path=r["path"],
        )
        if r["success"]:
            assert allowed, f"a denied action was recorded as success: {r} ({reason})"


def test_cross_user_work_mkdir_is_never_recorded_as_success(sample_log: Path) -> None:
    """The signal the demo exists to surface: writing into another user's work area must fail.

    A mkdir under work/<someone-else> is exactly the over-privilege attempt the report is meant
    to flag, so it may never be generated as a success and quietly drop out of the failure set.
    """
    cross_user = [
        r for r in _load(str(sample_log))
        if r["zone"] == "work" and r["operation"] == "mkdir" and not r["is_owner"]
    ]
    assert cross_user, "the sample data should contain cross-user mkdir attempts to reason about"
    for r in cross_user:
        assert owner_of_path(r["path"]) != r["actor"], "is_owner=False contradicts the path's owner"
        assert not r["success"], f"a mkdir into another user's work area succeeded: {r}"


def test_classify_failures_matches_independent_count(sample_log: Path) -> None:
    """classify_failures' violation total must equal an independent policy re-evaluation."""
    rows = [r for r in _load(str(sample_log)) if not r["success"]]
    expected_violations = sum(
        1
        for r in rows
        if not evaluate_policy(
            r["zone"], r["operation"], r["actor_role"], r["is_owner"],
            actor=r["actor"], path=r["path"],
        )[0]
    )
    out = classify_failures.invoke({"log_path": str(sample_log)})
    m = re.search(r"violations:\s*(\d+)", out)
    assert m and int(m.group(1)) == expected_violations, out


def test_policy_summary_mentions_every_zone() -> None:
    policy = json.loads((REPO / "data" / "policy_rules.json").read_text())
    summary = get_policy_summary.invoke({})
    for zone in policy["zones"]:
        assert zone in summary
