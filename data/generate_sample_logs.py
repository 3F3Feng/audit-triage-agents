#!/usr/bin/env python3
"""Generate **synthetic** audit logs for the demo.

Everything here is randomly generated: there is no real account, path or hostname in the output.
The schema mirrors the shape of authorization audit events commonly seen in production.
"""
from __future__ import annotations

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

USERS = ["a.chen", "d.olivares", "h.cassidy", "j.goran", "m.philip", "r.novak", "temp_contractor"]
ADMINS = {"r.novak"}
SHOWS = ["SHOWA", "SHOWB", "SHOWC"]
DEPTS = ["film", "television", "design"]

OPS = ["create", "modify", "delete", "chmod", "chown", "mkdir"]
# Weighting of ordinary versus suspicious activity.
WEIGHTS = {"create": 40, "mkdir": 25, "modify": 12, "delete": 6, "chmod": 5, "chown": 2}

FAILURE_REASONS = {
    "product_readonly": "Product area is read-only. Modifications and deletions are not allowed.",
    "not_owner": "Caller does not own the target path",
    "no_posix_write": "lack corresponding POSIX write permission bits on the file/folder",
    "not_in_group": "Caller group not permitted for this zone",
    "outside_zone": "Path is outside the permitted zone for this caller",
}


def make_event(ts: datetime, user: str) -> dict:
    op = random.choices(OPS, weights=[WEIGHTS[o] for o in OPS])[0]
    dept, show = random.choice(DEPTS), random.choice(SHOWS)

    # Three zones.
    zone = random.choices(["work", "product", "user_profile"], weights=[55, 35, 10])[0]
    if zone == "work":
        path = f"/studio/{dept}/devrnd/sequence/{show}/work/{user}/scene"
    elif zone == "product":
        path = f"/studio/{dept}/{show}/product/v1/scene"
    else:
        path = f"/studio/users/{user}/profile"

    # Attempts to exceed privilege: a non-admin touching the product zone.
    is_admin = user in ADMINS
    suspicious = (zone == "product" and op in {"modify", "delete", "chmod", "chown"} and not is_admin)

    # Other sporadic failures.
    rolled = random.random()
    if suspicious or (not is_admin and rolled < 0.07):
        outcome, reason_key = "failure", random.choice(list(FAILURE_REASONS))
    else:
        outcome, reason_key = "success", None

    return {
        "ts": ts.isoformat().replace("+00:00", "Z"),
        "level": "WARNING" if outcome == "failure" else "INFO",
        "logger": "audit",
        "event": "authorization",
        "operation": op,
        "actor": user,
        "path": path,
        "zone": zone,
        "outcome": outcome,
        "success": outcome == "success",
        "reason": FAILURE_REASONS.get(reason_key) if reason_key else None,
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
