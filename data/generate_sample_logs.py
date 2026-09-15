#!/usr/bin/env python3
"""Generate **synthetic** audit logs for the demo.

Everything here is randomly generated: there is no real account, path or hostname in the output.
The schema mirrors the shape of authorization audit events commonly seen in production.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Share the one policy engine, so an event's outcome is decided by the same code the triage
# tools use to judge it later. See tools/policy.py.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.policy import evaluate_policy, load_policy  # noqa: E402

_POLICY = load_policy()

# Each actor has a stable role. Admin roles must match policy["admin_roles"]; everyone else is a
# non-admin production role. r.novak is the only admin, so non-admins in the product zone stand out.
ROLE_BY_USER = {
    "a.chen": "artist",
    "d.olivares": "artist",
    "h.cassidy": "lighting_td",
    "j.goran": "artist",
    "m.philip": "coordinator",
    "r.novak": "pipeline_admin",
    "temp_contractor": "contractor",
}
USERS = list(ROLE_BY_USER)
SHOWS = ["SHOWA", "SHOWB", "SHOWC"]
DEPTS = ["film", "television", "design"]

OPS = ["create", "modify", "delete", "chmod", "chown", "mkdir"]
# Weighting of ordinary versus suspicious activity.
WEIGHTS = {"create": 40, "mkdir": 25, "modify": 12, "delete": 6, "chmod": 5, "chown": 2}

# Sporadic failures on operations the policy *allows* (POSIX bits, group config) — these are
# permission errors, not policy violations, and the triage layer must tell them apart.
POSIX_FAILURE_REASONS = [
    "lack corresponding POSIX write permission bits on the file/folder",
    "Caller group not permitted for this zone",
]


def _violation_reason(zone: str, is_owner: bool) -> str:
    if zone == "product":
        return "Product area is read-only. Modifications and deletions are not allowed."
    if not is_owner:
        return "Caller does not own the target path"
    return "Path is outside the permitted zone for this caller"


def make_event(ts: datetime, user: str) -> dict:
    role = ROLE_BY_USER[user]
    op = random.choices(OPS, weights=[WEIGHTS[o] for o in OPS])[0]
    dept, show = random.choice(DEPTS), random.choice(SHOWS)
    zone = random.choices(["work", "product", "user_profile"], weights=[55, 35, 10])[0]

    # Ownership: in work/user_profile you usually act on your own directory, but ~12% of the time
    # on someone else's (is_owner=False). The product zone has no per-user owner.
    if zone == "product":
        is_owner = False
        path = f"/studio/{dept}/{show}/product/v1/scene"
    else:
        owner = user if random.random() > 0.12 else random.choice([u for u in USERS if u != user])
        is_owner = owner == user
        if zone == "work":
            path = f"/studio/{dept}/devrnd/sequence/{show}/work/{owner}/scene"
        else:
            path = f"/studio/users/{owner}/profile"

    # Outcome is decided by the shared policy engine: a denied action fails as a violation; an
    # allowed action mostly succeeds but occasionally hits a sporadic permission error.
    allowed, _ = evaluate_policy(zone, op, role, is_owner, _POLICY)
    if not allowed:
        outcome, reason = "failure", _violation_reason(zone, is_owner)
    elif random.random() < 0.05:
        outcome, reason = "failure", random.choice(POSIX_FAILURE_REASONS)
    else:
        outcome, reason = "success", None

    return {
        "ts": ts.isoformat().replace("+00:00", "Z"),
        "level": "WARNING" if outcome == "failure" else "INFO",
        "logger": "audit",
        "event": "authorization",
        "operation": op,
        "actor": user,
        "actor_role": role,
        "path": path,
        "zone": zone,
        "is_owner": is_owner,
        "outcome": outcome,
        "success": outcome == "success",
        "reason": reason,
        "client_ip": f"10.{random.randint(0, 40)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "task": random.choice(["sq010_sh010", "sq010_sh020", "ep102_0020", "cut_004"]),
        "request_id": str(uuid.uuid4()),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--out", default="data/sample_audit_logs.jsonl")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    random.seed(args.seed)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Make one non-admin account look unusually active, so there is a signal worth analysing.
    noisy_user = "temp_contractor"
    start = datetime.now(timezone.utc) - timedelta(hours=8)
    rows = []
    for i in range(args.n):
        ts = start + timedelta(seconds=i * (8 * 3600 / max(args.n, 1)))
        user = noisy_user if random.random() < 0.22 else random.choice(USERS)
        rows.append(make_event(ts, user))

    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    fails = sum(1 for r in rows if not r["success"])
    print(f"  {len(rows)} events -> {out} ({fails} failures)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
