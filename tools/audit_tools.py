"""LangChain tool layer: deterministic work lives here, so the LLM never has to do arithmetic.

Every function is decorated with @tool and returns compact text that can be fed straight to an
LLM (this keeps token usage down and stops agents from having to page through thousands of raw
JSON lines).
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from .policy import evaluate_policy, load_policy


#: Fields every tool below indexes directly. A row missing one of these cannot be reasoned about,
#: so it is rejected at load time with a message naming the line -- rather than surfacing later as
#: a KeyError from somewhere deep in a report.
REQUIRED_FIELDS = ("ts", "operation", "actor", "zone", "path")


class AuditLogError(ValueError):
    """An audit log could not be read: malformed JSON, or a row missing a required field.

    Distinct from FileNotFoundError so the service layer can tell "you sent me bad input" (4xx)
    apart from "that file isn't here" (404) and from a genuine internal fault (5xx).
    """


def _load(path: str) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"audit log not found: {p}")
    rows: list[dict[str, Any]] = []
    for lineno, line in enumerate(p.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditLogError(f"{p.name} line {lineno}: not valid JSON ({exc.msg})") from exc
        if not isinstance(row, dict):
            raise AuditLogError(
                f"{p.name} line {lineno}: expected a JSON object, got {type(row).__name__}"
            )
        missing = [f for f in REQUIRED_FIELDS if f not in row]
        if missing:
            raise AuditLogError(
                f"{p.name} line {lineno}: missing required field(s): {', '.join(missing)}"
            )
        rows.append(row)
    return rows


def time_window(rows: list[dict[str, Any]]) -> tuple[str, str]:
    """Earliest and latest timestamp in ``rows``, whatever order they arrive in.

    Audit logs are not guaranteed sorted (merged shards, concurrent writers), and taking the
    first and last row on faith yields a window that runs backwards. ISO-8601 UTC stamps sort
    lexicographically, which is also how list_failures orders its output.
    """
    stamps = [r["ts"] for r in rows]
    return min(stamps), max(stamps)


@tool
def summarize_events(log_path: str, top_n: int = 5) -> str:
    """Summarize the overall shape of an audit log: totals, successes/failures, operation mix, busiest actors."""
    rows = _load(log_path)
    if not rows:
        return "No events."
    ops = Counter(r["operation"] for r in rows)
    actors = Counter(r["actor"] for r in rows)
    fails = [r for r in rows if not r.get("success")]
    first, last = time_window(rows)
    lines = [
        f"total events: {len(rows)}",
        f"failures: {len(fails)} ({len(fails) / max(len(rows), 1):.1%})",
        f"time range: {first} -> {last}",
        "",
        "operations:",
        *[f"  - {k}: {v}" for k, v in ops.most_common()],
        "",
        f"busiest actors (top {top_n}):",
        *[f"  - {k}: {v}" for k, v in actors.most_common(top_n)],
    ]
    return "\n".join(lines)


@tool
def list_failures(log_path: str, limit: int = 30) -> str:
    """List failed authorization events (with reason and path), newest first, for suspicious-activity review."""
    rows = [r for r in _load(log_path) if not r.get("success")]
    rows.sort(key=lambda r: r["ts"], reverse=True)
    if not rows:
        return "No failed events."
    out = []
    for i, r in enumerate(rows[:limit], 1):
        owner = "owner" if r.get("is_owner") else "non-owner"
        out.append(
            f"#{i} {r['ts']} | {r['actor']:<16} {('[' + str(r.get('actor_role', '?')) + ']'):<14} | "
            f"{r['operation']:<6} | {r['zone']:<12} {owner:<9} | {r['path']}\n    reason: {r.get('reason')}"
        )
    return f"{len(rows)} failed events in total, showing the most recent {min(limit, len(rows))}:\n\n" + "\n".join(out)


@tool
def group_by_actor(log_path: str, only_failures: bool = True) -> str:
    """Aggregate by actor: operations, failures, failure rate and the zones each actor touched."""
    rows = _load(log_path)
    stats: dict[str, dict[str, Any]] = {}
    for r in rows:
        if only_failures and r.get("success"):
            continue
        s = stats.setdefault(
            r["actor"],
            {"role": r.get("actor_role", "?"), "total": 0, "fail": 0, "zones": Counter(), "ops": Counter()},
        )
        s["total"] += 1
        s["fail"] += 0 if r.get("success") else 1
        s["zones"][r["zone"]] += 1
        s["ops"][r["operation"]] += 1
    lines = []
    for actor, s in sorted(stats.items(), key=lambda kv: -kv[1]["fail"]):
        lines.append(
            f"{actor:<18} [{s['role']:<13}] failures {s['fail']:>3} / total {s['total']:>3} | "
            f"zones {dict(s['zones'])} | ops {dict(s['ops'].most_common(3))}"
        )
    return "\n".join(lines) or "No matching records."


@tool
def check_policy(
    zone: str,
    operation: str,
    role: str,
    is_owner: bool,
    actor: str = "",
    path: str = "",
) -> str:
    """Evaluate a single operation against the policy file. Returns ALLOW or DENY plus the reason.

    Admin-ness is decided from the role (the policy lists which roles are admin), not passed in.

    Args:
        zone: product / work / user_profile
        operation: create / modify / delete / chmod / chown / mkdir
        role: the caller's role, e.g. from an event's actor_role field (see get_policy_summary
              for which roles are admin)
        is_owner: whether the caller owns the target path
        actor: the calling user, from an event's actor field. Pass it together with path for
               work-zone mkdir, where the policy allows bootstrapping one's *own* directory only.
        path: the target path, from an event's path field (see actor)
    """
    policy = load_policy()
    if zone not in policy["zones"]:
        return f"UNKNOWN_ZONE: {zone}"
    allowed, reason = evaluate_policy(
        zone, operation, role, is_owner, policy, actor=actor or None, path=path or None
    )
    return f"{'ALLOW' if allowed else 'DENY'}: {reason}"


@tool
def classify_failures(log_path: str, limit: int = 40) -> str:
    """Label every failed event as VIOLATION or PERMISSION_ERROR, grounded in the event's own fields.

    For each failure this re-evaluates the policy from the event's actor_role + is_owner:
      * VIOLATION        — the policy forbids the action (a genuine over-privilege attempt)
      * PERMISSION_ERROR — the policy allows it, but it failed for another reason (e.g. POSIX bits)

    The verdict comes from a deterministic function, not the LLM's judgement, so it is reproducible.
    Returns the violation/permission-error totals, a per-actor breakdown, and violation evidence.
    """
    rows = [r for r in _load(log_path) if not r.get("success")]
    if not rows:
        return "No failed events."
    policy = load_policy()

    per_actor: dict[str, dict[str, Any]] = {}
    violations: list[dict[str, Any]] = []
    for r in rows:
        allowed, _ = evaluate_policy(
            r["zone"], r["operation"], r.get("actor_role", ""), bool(r.get("is_owner")), policy,
            actor=r["actor"], path=r["path"],
        )
        label = "PERMISSION_ERROR" if allowed else "VIOLATION"
        pa = per_actor.setdefault(
            r["actor"], {"role": r.get("actor_role", "?"), "VIOLATION": 0, "PERMISSION_ERROR": 0}
        )
        pa[label] += 1
        if label == "VIOLATION":
            violations.append(r)

    n_viol = len(violations)
    n_perm = len(rows) - n_viol
    lines = [
        "failure classification (grounded in actor_role + is_owner, deterministic):",
        f"total failures: {len(rows)} | violations: {n_viol} | permission errors: {n_perm}",
        "",
        "by actor (violations / permission-errors):",
    ]
    for actor, pa in sorted(per_actor.items(), key=lambda kv: -kv[1]["VIOLATION"]):
        lines.append(
            f"  {actor:<18} [{pa['role']:<13}] {pa['VIOLATION']:>3} / {pa['PERMISSION_ERROR']:>3}"
        )
    violations.sort(key=lambda r: r["ts"], reverse=True)
    lines += ["", f"violations (evidence), newest first, showing up to {limit}:"]
    for r in violations[:limit]:
        lines.append(
            f"  {r['ts']} | {r['actor']:<16} [{r.get('actor_role', '?')}] | "
            f"{r['operation']:<6} | {r['zone']:<12} | {r['path']}"
        )
    return "\n".join(lines)


@tool
def get_policy_summary() -> str:
    """Return the current authorization policy so an analyst can line its findings up with policy text."""
    policy = load_policy()
    lines = [f"policy version {policy['version']}, admin roles: {', '.join(policy['admin_roles'])}", ""]
    for zone, spec in policy["zones"].items():
        lines.append(f"[{zone}] {spec['intent']}")
        for op, who in spec["allow"].items():
            lines.append(f"    {op:<8} -> {', '.join(who)}")
        lines.append("")
    lines.append("notes:")
    lines += [f"  - {n}" for n in policy["notes"]]
    return "\n".join(lines)


ALL_TOOLS = [
    summarize_events,
    list_failures,
    group_by_actor,
    check_policy,
    classify_failures,
    get_policy_summary,
]
