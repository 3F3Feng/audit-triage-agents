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


def owner_of_path(path: str) -> str | None:
    """Return the user a path belongs to, or ``None`` when the path names no owner.

    Work and profile paths carry the owning user in the segment right after the zone marker::

        /studio/<dept>/devrnd/sequence/<show>/work/<owner>/scene
        /studio/users/<owner>/profile

    Product paths are a shared delivery area and have no per-user owner.
    """
    parts = [p for p in path.split("/") if p]
    for marker in ("work", "users"):
        if marker in parts:
            i = parts.index(marker)
            if i + 1 < len(parts):
                return parts[i + 1]
    return None


def evaluate_policy(
    zone: str,
    operation: str,
    role: str,
    is_owner: bool,
    policy: dict[str, Any] | None = None,
    *,
    actor: str | None = None,
    path: str | None = None,
) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for one operation.

    Args:
        zone: product / work / user_profile
        operation: create / modify / delete / chmod / chown / mkdir
        role: the caller's role; admin roles are listed in ``policy["admin_roles"]``
        is_owner: whether the caller owns the target path
        policy: a pre-loaded policy dict (optional; loaded from disk if omitted)
        actor: the calling user; required to decide a ``self_bootstrap`` grant
        path: the target path; required to decide a ``self_bootstrap`` grant

    ``self_bootstrap`` is the one rule that cannot be decided from role and ownership alone: a
    user may create their *own* ``work/<username>`` directory before they own it. Deciding that
    needs the caller's name and the directory being created, so without both this denies rather
    than guesses -- otherwise the grant would hand every caller a write into anyone's work area.
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
        target_owner = owner_of_path(path) if path else None
        if actor and target_owner == actor:
            return True, f"{actor} may bootstrap their own directory in zone {zone}"
        if actor and target_owner:
            return False, (
                f"{operation} in zone {zone} may only bootstrap one's own directory "
                f"(the path belongs to {target_owner}, the caller is {actor})"
            )
        return False, (
            f"{operation} in zone {zone} is limited to bootstrapping one's own directory; "
            f"the caller and target path are needed to decide (actor={actor!r}, path={path!r})"
        )

    needed = "an admin role" if "admin" in rule else "owner rights"
    return False, f"{operation} in zone {zone} requires {needed} (role={role}, owner={is_owner})"
