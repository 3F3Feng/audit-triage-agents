#!/usr/bin/env python3
"""Service layer: expose the audit-triage crew over HTTP.

    uvicorn server:app --port 8000

Why this exists: a CLI calling Python functions directly only proves "the script runs". Putting
the crew behind a service boundary proves "other systems can call it" -- which is the line between
agent engineering and a notebook demo.
"""
from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from typesafe_sdk import TypeSafeError

from agents.triage_crew import DEFAULT_BASE_URL, DEFAULT_MODEL, build_crew
from tools import actor_assessment
from tools.audit_tools import AuditLogError, _load, time_window

REPO = Path(__file__).resolve().parent

app = FastAPI(
    title="Audit Triage Service",
    description="Multi-agent audit-triage prototype (LangChain tools + CrewAI crew). Synthetic data only.",
    version="0.1.0",
)


class TriageRequest(BaseModel):
    logs: str = Field(default="data/sample_audit_logs.jsonl", description="Audit log path (relative to the repo root, or absolute)")
    write_report: bool = Field(default=True, description="Whether to write the report back to report.md")


class TriageResponse(BaseModel):
    report: str
    elapsed_seconds: float
    stats: dict[str, Any]
    report_path: str | None = None


def _resolve(p: str) -> Path:
    path = Path(p)
    return path if path.is_absolute() else (REPO / path)


def _stats(log_path: Path) -> dict[str, Any]:
    """Deterministic statistics -- independent of the LLM, so agent output can be cross-checked."""
    rows = _load(str(log_path))
    fails = [r for r in rows if not r.get("success")]
    return {
        "events": len(rows),
        "failures": len(fails),
        "failure_rate": round(len(fails) / max(len(rows), 1), 4),
        "operations": dict(Counter(r["operation"] for r in rows).most_common()),
        "zones": dict(Counter(r["zone"] for r in rows).most_common()),
        "top_actors_by_failure": dict(
            Counter(r["actor"] for r in fails).most_common(5)
        ),
        "window": list(time_window(rows)) if rows else [],
    }


def _stats_or_400(log_path: Path) -> dict[str, Any]:
    """Read and summarize a log, turning a malformed one into a 4xx the caller can act on.

    A bad log is the caller's input, not a server fault, so it must not surface as a 500.
    """
    try:
        return _stats(log_path)
    except AuditLogError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "model": DEFAULT_MODEL,
        "base_url": DEFAULT_BASE_URL,
        "typesafe_configured": actor_assessment.is_configured(),
        "repo": str(REPO),
    }


@app.get("/policies")
def policies() -> dict[str, Any]:
    return json.loads((REPO / "data" / "policy_rules.json").read_text())


@app.get("/events/summary")
def events_summary(logs: str = "data/sample_audit_logs.jsonl") -> dict[str, Any]:
    """A purely deterministic summary that never touches an LLM -- proof that the tool layer is reproducible on its own."""
    log_path = _resolve(logs)
    if not log_path.exists():
        raise HTTPException(status_code=404, detail=f"log not found: {log_path}")
    return _stats_or_400(log_path)


@app.get("/actors/assessment")
def actors_assessment(logs: str = "data/sample_audit_logs.jsonl", top_n: int = 5) -> dict[str, Any]:
    """Typed per-actor intent + concern from TypeSafe, with the recommended action from code thresholds.

    Sub-second, so it can gate the minute-long crew rather than follow it.
    """
    log_path = _resolve(logs)
    if not log_path.exists():
        raise HTTPException(status_code=404, detail=f"log not found: {log_path}")
    if not 1 <= top_n <= 50:
        raise HTTPException(status_code=400, detail="top_n must be between 1 and 50")
    _stats_or_400(log_path)  # validate before spending a model call
    started = time.perf_counter()
    try:
        actors = actor_assessment.assess_actors(str(log_path), top_n)
    except actor_assessment.AssessmentUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"TypeSafe not configured: {exc}") from exc
    except TypeSafeError as exc:
        raise HTTPException(status_code=502, detail=f"TypeSafe call failed: {exc}") from exc
    return {"actors": actors, "elapsed_seconds": round(time.perf_counter() - started, 2)}


@app.post("/triage", response_model=TriageResponse)
def triage(req: TriageRequest) -> TriageResponse:
    log_path = _resolve(req.logs)
    if not log_path.exists():
        raise HTTPException(status_code=404, detail=f"log not found: {log_path}")
    # Validate before spending a model call: a log the tools cannot read would only fail later,
    # after the crew has already run.
    stats = _stats_or_400(log_path)

    started = time.perf_counter()
    try:
        crew = build_crew(str(log_path))
        result = crew.kickoff()
    except Exception as exc:  # keep "the model/orchestration failed" distinct from "the logic failed"
        raise HTTPException(
            status_code=502,
            detail=f"crew execution failed (check that the model endpoint behind TRIAGE_BASE_URL is up): {exc}",
        ) from exc
    elapsed = time.perf_counter() - started

    report = str(result)
    out_path: Path | None = None
    if req.write_report:
        out_path = REPO / "report.md"
        out_path.write_text(report)

    return TriageResponse(
        report=report,
        elapsed_seconds=round(elapsed, 2),
        stats=stats,
        report_path=str(out_path) if out_path else None,
    )
