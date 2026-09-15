"""Deterministic authorization-policy engine.

This is the **single source of truth** shared by two places that must never disagree:
  * `tools/audit_tools.py`      — checks events against policy at triage time
  * `data/generate_sample_logs.py` — decides each synthetic event's outcome

Because both import the same `evaluate_policy`, a generated event's success/failure and the
analyst's later verdict are grounded in one implementation — they cannot drift apart. Admin-ness
is never passed in as a pre-decided boolean; callers pass a *role*, and this module decides
whether that role is an admin by checking membership in `policy["admin_roles"]`.

Intentionally dependency-free (stdlib only) so the data generator stays lightweight.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

POLICY_PATH = Path(__file__).resolve().parent.parent / "data" / "policy_rules.json"


def load_policy(path: Path | None = None) -> dict[str, Any]:
    return json.loads((path or POLICY_PATH).read_text())


def evaluate_policy(
    zone: str,
    operation: str,
    role: str,
    is_owner: bool,
    policy: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for one operation.

    Args:
        zone: product / work / user_profile
        operation: create / modify / delete / chmod / chown / mkdir
        role: the caller's role; admin roles are listed in ``policy["admin_roles"]``
        is_owner: whether the caller owns the target path
        policy: a pre-loaded policy dict (optional; loaded from disk if omitted)
    """
    policy = policy or load_policy()
    zones = policy["zones"]
    if zone not in zones:
        return False, f"unknown zone {zone!r}"

    rule = zones[zone]["allow"].get(operation)
    if rule is None:
        return False, f"policy does not define {operation} in zone {zone} (deny by default)"

    is_admin = role in policy["admin_roles"]
    if "*" in rule:
        return True, f"zone {zone} permits {operation} for all users"
    if "admin" in rule and is_admin:
        return True, f"an admin role ({role}) may {operation} in zone {zone}"
    if "owner" in rule and is_owner:
        return True, f"the owner may {operation} in zone {zone}"
    if "self_bootstrap" in rule:
        return True, "permitted to bootstrap one's own work directory"

    needed = "an admin role" if "admin" in rule else "owner rights"
    return False, f"{operation} in zone {zone} requires {needed} (role={role}, owner={is_owner})"
