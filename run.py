#!/usr/bin/env python3
"""Entry point: run the audit-triage crew once.

    python run.py --logs data/sample_audit_logs.jsonl --out report.md
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agents.triage_crew import build_crew  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default="data/sample_audit_logs.jsonl")
    ap.add_argument("--out", default="report.md")
    args = ap.parse_args()

    if not Path(args.logs).exists():
        print(f"{args.logs} not found -- run: python data/generate_sample_logs.py")
        return 1

    crew = build_crew(str(Path(args.logs).resolve()))
    result = crew.kickoff()

    Path(args.out).write_text(str(result))
    print(f"\n>> report written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
