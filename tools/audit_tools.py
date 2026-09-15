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

POLICY_PATH = Path(__file__).resolve().parent.parent / "data" / "policy_rules.json"


def _load(path: str) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"audit log not found: {p}")
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


@tool
def summarize_events(log_path: str, top_n: int = 5) -> str:
    """Summarize the overall shape of an audit log: totals, successes/failures, operation mix, busiest actors."""
    rows = _load(log_path)
    ops = Counter(r["operation"] for r in rows)
    actors = Counter(r["actor"] for r in rows)
    fails = [r for r in rows if not r.get("success")]
    lines = [
        f"total events: {len(rows)}",
        f"failures: {len(fails)} ({len(fails) / max(len(rows), 1):.1%})",
        f"time range: {rows[0]['ts']} -> {rows[-1]['ts']}",
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
        out.append(
            f"#{i} {r['ts']} | {r['actor']:<16} | {r['operation']:<6} | {r['zone']:<12} | "
            f"{r['path']}\n    reason: {r.get('reason')}"
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
        s = stats.setdefault(r["actor"], {"total": 0, "fail": 0, "zones": Counter(), "ops": Counter()})
        s["total"] += 1
        s["fail"] += 0 if r.get("success") else 1
        s["zones"][r["zone"]] += 1
        s["ops"][r["operation"]] += 1
    lines = []
    for actor, s in sorted(stats.items(), key=lambda kv: -kv[1]["fail"]):
        lines.append(
            f"{actor:<18} failures {s['fail']:>3} / total {s['total']:>3} | "
            f"zones {dict(s['zones'])} | ops {dict(s['ops'].most_common(3))}"
        )
    return "\n".join(lines) or "No matching records."


@tool
def check_policy(zone: str, operation: str, is_admin: bool, is_owner: bool) -> str:
    """Evaluate a single operation against the policy file. Returns ALLOW or DENY plus the reason.

    Args:
        zone: product / work / user_profile
        operation: create / modify / delete / chmod / chown / mkdir
        is_admin: whether the caller holds an admin role
        is_owner: whether the caller owns the target path
    """
    policy = json.loads(POLICY_PATH.read_text())
    zones = policy["zones"]
    if zone not in zones:
        return f"UNKNOWN_ZONE: {zone}"
    rule = zones[zone]["allow"].get(operation)
    if rule is None:
        return f"DENY: policy does not define {operation} in zone {zone} (deny by default)"
    if "*" in rule:
        return f"ALLOW: zone {zone} permits {operation} for all users"
    if "admin" in rule and is_admin:
        return f"ALLOW: an admin role may {operation} in zone {zone}"
    if "owner" in rule and is_owner:
        return f"ALLOW: the owner may {operation} in zone {zone}"
    if "self_bootstrap" in rule:
        return "ALLOW: permitted to bootstrap one's own work directory"
    needed = "the admin role" if "admin" in rule else "owner rights"
    return f"DENY: {operation} in zone {zone} requires {needed}"


@tool
def get_policy_summary() -> str:
    """Return the current authorization policy so an analyst can line its findings up with policy text."""
    policy = json.loads(POLICY_PATH.read_text())
    lines = [f"policy version {policy['version']}, admin roles: {', '.join(policy['admin_roles'])}", ""]
    for zone, spec in policy["zones"].items():
        lines.append(f"[{zone}] {spec['intent']}")
        for op, who in spec["allow"].items():
            lines.append(f"    {op:<8} -> {', '.join(who)}")
        lines.append("")
    lines.append("notes:")
    lines += [f"  - {n}" for n in policy["notes"]]
    return "\n".join(lines)


ALL_TOOLS = [summarize_events, list_failures, group_by_actor, check_policy, get_policy_summary]
