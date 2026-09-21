"""Per-actor intent assessment: typed judgments from TypeSafe's System One model (Jev).

Division of labour, same spine as the rest of the repo:
  * code decides the facts -- which failures are VIOLATION vs PERMISSION_ERROR comes from
    `evaluate_policy`, and those labels are handed to the model as *state*, never asked of it
  * the model answers the one thing code can't: what a pattern of failures most likely means
    (probing vs a broken script vs honest slips) and how hard a reviewer should follow up
  * code decides what to *do* with those answers -- the thresholds below are explicit policy,
    not something the model is asked to pick

Answers come back typed (a label plus a probability per option), so they can be tested,
thresholded and ranked without parsing prose -- and a call takes well under a second, versus
about a minute for the full crew.
"""
from __future__ import annotations

import os
from collections import Counter
from typing import Any

from langchain_core.tools import tool
from typesafe_sdk import Choice, Score, TypeSafeClient

from .audit_tools import _load
from .policy import evaluate_policy, load_policy

API_KEY_ENV = "TYPESAFE_API_KEY"

#: Cap on the failed events sent per actor: enough to show a pattern, bounded in tokens.
MAX_EVENTS_PER_ACTOR = 20

# --- escalation policy (code-owned; tune on real outcomes, these are starting points) --------
#: Below this confidence on either answer, the model's view is too split to act on alone.
MIN_CONFIDENCE = 0.5
#: Concern score (0-3 scale, see CONCERN_LEVELS) at or above which we escalate / follow up.
ESCALATE_AT = 2.5
FOLLOW_UP_AT = 1.5

EXPLANATIONS = {
    "probing": (
        "Deliberately testing access boundaries: attempts that reach into other users' areas "
        "or protected zones, often across several paths or operations"
    ),
    "misconfigured_automation": (
        "A script, tool or pipeline repeating the same wrong operation, typically on the same or "
        "near-identical paths"
    ),
    "honest_mistake": "Scattered, plausible user slips with no consistent target",
    "unclear": "The evidence does not support any of the other explanations over the rest",
}

CONCERN_LEVELS = [
    "Routine noise: nothing a reviewer needs to follow up on",
    "Worth a line in the weekly access review, no direct action",
    "Follow up with the user or their lead this week",
    "Escalate to security today",
]

QUESTIONS = {
    "explanation": Choice(
        instructions=(
            "Each entry in `failed_events` is a denied file operation by `actor`. `verdict` on each "
            "event is already decided by the policy engine: VIOLATION means the policy forbids the "
            "action for this role and ownership, PERMISSION_ERROR means the policy allows it but it "
            "failed for another reason. `violation_rate` is the actor's violations per event and "
            "`org_baseline` shows the same rate across every actor, so an actor near the median is "
            "behaving like everyone else. What best explains this actor's pattern of failures?"
        ),
        criteria=EXPLANATIONS,
    ),
    "concern": Score(
        instructions=(
            "Given the actor's role, the policy verdicts on their failed events, the zones and paths "
            "involved, and how their `violation_rate` compares with `org_baseline`, how strongly "
            "should a security reviewer follow up on this actor?"
        ),
        criteria=CONCERN_LEVELS,
    ),
}


class AssessmentUnavailable(RuntimeError):
    """TypeSafe is not configured (no API key), so no assessment can be made."""


def is_configured() -> bool:
    return bool(os.environ.get(API_KEY_ENV, "").strip())


def build_actor_states(
    rows: list[dict[str, Any]], top_n: int = 5, policy: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Deterministic: pick the ``top_n`` actors by failure count and assemble each one's state.

    Every failed event carries its policy verdict, so the model reasons over decided facts.
    """
    policy = policy or load_policy()
    fails = [r for r in rows if not r.get("success")]
    totals = Counter(r["actor"] for r in rows)
    ranked = Counter(r["actor"] for r in fails).most_common(top_n)
    baseline = _org_baseline(rows, fails, totals, policy)

    states = []
    for actor, n_fail in ranked:
        events = sorted((r for r in fails if r["actor"] == actor), key=lambda r: r["ts"], reverse=True)
        verdicts = Counter()
        evidence = []
        for r in events:
            allowed, _ = evaluate_policy(
                r["zone"], r["operation"], r.get("actor_role", ""), bool(r.get("is_owner")), policy,
                actor=r["actor"], path=r["path"],
            )
            verdict = "PERMISSION_ERROR" if allowed else "VIOLATION"
            verdicts[verdict] += 1
            if len(evidence) < MAX_EVENTS_PER_ACTOR:
                evidence.append({
                    "ts": r["ts"], "operation": r["operation"], "zone": r["zone"], "path": r["path"],
                    "is_owner": bool(r.get("is_owner")), "reason": r.get("reason"), "verdict": verdict,
                })
        states.append({
            "actor": actor,
            "role": events[0].get("actor_role", "unknown"),
            "total_events": totals[actor],
            "failed_events_total": n_fail,
            "violations": verdicts["VIOLATION"],
            "permission_errors": verdicts["PERMISSION_ERROR"],
            "violation_rate": round(verdicts["VIOLATION"] / totals[actor], 3),
            "org_baseline": baseline,
            "zone_intents": {z: spec["intent"] for z, spec in policy["zones"].items()},
            "failed_events_shown": len(evidence),
            "failed_events": evidence,
        })
    return states


def _org_baseline(
    rows: list[dict[str, Any]], fails: list[dict[str, Any]], totals: Counter, policy: dict[str, Any]
) -> dict[str, Any]:
    """What 'normal' looks like across every actor, so one actor's numbers have a comparison.

    Without it, a handful of cross-user denials reads as probing in isolation even when every
    user in the org produces about as many.
    """
    violations = Counter(
        r["actor"] for r in fails
        if not evaluate_policy(
            r["zone"], r["operation"], r.get("actor_role", ""), bool(r.get("is_owner")), policy,
            actor=r["actor"], path=r["path"],
        )[0]
    )
    rates = sorted(violations[a] / n for a, n in totals.items())
    return {
        "actors": len(totals),
        "median_violation_rate": round(rates[len(rates) // 2], 3) if rates else 0.0,
        "max_violation_rate": round(rates[-1], 3) if rates else 0.0,
    }


def decide_action(explanation: dict[str, Any], concern: dict[str, Any]) -> str:
    """Code-owned policy mapping the two typed answers to what a reviewer should do."""
    if min(explanation["confidence"], concern["confidence"]) < MIN_CONFIDENCE:
        return "human_review"
    if concern["score"] >= ESCALATE_AT:
        return "escalate"
    if concern["score"] >= FOLLOW_UP_AT:
        return "follow_up"
    return "note"


def assess_actors(
    log_path: str, top_n: int = 5, client: TypeSafeClient | None = None
) -> list[dict[str, Any]]:
    """Assess the ``top_n`` actors by failure count, most concerning first.

    Raises AssessmentUnavailable when no key is configured and no client is supplied;
    TypeSafe transport/API failures propagate as ``typesafe_sdk.TypeSafeError``.
    """
    states = build_actor_states(_load(log_path), top_n)
    if not states:
        return []
    if client is None and not is_configured():
        raise AssessmentUnavailable(f"{API_KEY_ENV} is not set")

    owns_client = client is None
    client = client or TypeSafeClient()
    try:
        results = []
        for state in states:
            answers = client.system_one(state=state, questions=QUESTIONS).answers
            ex, co = answers["explanation"], answers["concern"]
            explanation = {"choice": ex.choice, "confidence": ex.confidence,
                           "probabilities": dict(ex.probabilities)}
            concern = {"score": co.score, "confidence": co.confidence,
                       "level": CONCERN_LEVELS[round(co.score)]}
            results.append({
                "actor": state["actor"],
                "role": state["role"],
                "failed_events_total": state["failed_events_total"],
                "violations": state["violations"],
                "permission_errors": state["permission_errors"],
                "explanation": explanation,
                "concern": concern,
                "action": decide_action(explanation, concern),
            })
    finally:
        if owns_client:
            client.close()
    results.sort(key=lambda r: -r["concern"]["score"])
    return results


@tool
def assess_actor_intent(log_path: str, top_n: int = 5) -> str:
    """Typed per-actor judgment of WHY each top-failing actor fails (probing / misconfigured
    automation / honest mistake / unclear) and how strongly to follow up (0-3), with probabilities.

    The violation counts are the policy engine's; the explanation and concern come from TypeSafe's
    Jev model; the recommended action comes from fixed thresholds in code.
    """
    try:
        results = assess_actors(log_path, top_n)
    except AssessmentUnavailable as exc:
        return f"assessment unavailable: {exc}"
    if not results:
        return "No failed events."
    lines = ["per-actor intent assessment (TypeSafe Jev; action from code thresholds), most concerning first:"]
    for r in results:
        ex, co = r["explanation"], r["concern"]
        lines.append(
            f"  {r['actor']:<18} [{r['role']:<13}] fails={r['failed_events_total']:>3} "
            f"viol={r['violations']:>3} | {ex['choice']} (p={ex['probabilities'][ex['choice']]:.2f}, "
            f"conf={ex['confidence']:.2f}) | concern={co['score']:.2f}/3 (conf={co['confidence']:.2f}) "
            f"-> {r['action']}"
        )
    return "\n".join(lines)
