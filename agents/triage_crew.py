"""CrewAI orchestration: three roles working sequentially to produce an audit-triage report.

Design rules:
  * deterministic work (aggregation, matching) goes to the LangChain tools
  * judgement and synthesis (which actor looks suspicious, how to rank risk, how to write it up)
    goes to the agents
"""
from __future__ import annotations

import os
from pathlib import Path

from crewai import LLM, Agent, Crew, Process, Task
from crewai.tools.base_tool import Tool as CrewTool
from dotenv import load_dotenv

from tools.audit_tools import ALL_TOOLS


# --- LangChain -> CrewAI bridge ---------------------------------------------------------------
# crewai 1.15+ only accepts its own BaseTool on Agent.tools: handing it a LangChain
# StructuredTool raises a ValidationError while the Agent is still being constructed.
# Bridge with crewai's Tool.from_langchain(). Note that the abstract BaseTool exposes a method
# of the same name, but calling that one raises
#   TypeError: Can't instantiate abstract class BaseTool with abstract method _run
# so the concrete Tool class is required.
# The bridge lives here, in the orchestration layer, so tools/audit_tools.py stays
# framework-agnostic and unit-testable.
CREW_TOOLS: list[CrewTool] = [CrewTool.from_langchain(t) for t in ALL_TOOLS]
CREW_TOOL_BY_NAME: dict[str, CrewTool] = {t.name: t for t in CREW_TOOLS}

REPO = Path(__file__).resolve().parent.parent

# Load repo-root .env (endpoint / key / model) so `cp .env.example .env` just works for
# `uvicorn server:app` and `python run.py`. Does not override vars already in the
# environment, so an explicit `export TRIAGE_MODEL=...` still wins.
load_dotenv(REPO / ".env")

DEFAULT_BASE_URL = os.environ.get("TRIAGE_BASE_URL", "http://localhost:8080/v1")
DEFAULT_MODEL = os.environ.get("TRIAGE_MODEL", "deepseek-flash")
DEFAULT_KEY = os.environ.get("TRIAGE_API_KEY", "local")


def build_llm() -> LLM:
    """Point at any OpenAI-compatible endpoint (self-hosted server or a cloud API)."""
    return LLM(model=f"openai/{DEFAULT_MODEL}", base_url=DEFAULT_BASE_URL, api_key=DEFAULT_KEY)


def build_crew(log_path: str) -> Crew:
    llm = build_llm()

    summarizer = Agent(
        role="Audit Event Summarizer",
        goal="Use the tools to establish the scale and shape of the audit log, with numbers that can be checked",
        backstory=(
            "You are the first stage of the pipeline: you gather evidence, you do not judge. "
            "Every number must come from a tool call; you never invent figures from memory."
        ),
        tools=[
            CREW_TOOL_BY_NAME["summarize_events"],
            CREW_TOOL_BY_NAME["list_failures"],
            CREW_TOOL_BY_NAME["group_by_actor"],
        ],
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )

    analyst = Agent(
        role="Authorization Policy Analyst",
        goal=(
            "Compare failures against the authorization policy, decide which are genuine violations "
            "and which are merely mis-clicks, and rank the actors by risk"
        ),
        backstory=(
            "You know least privilege and zone isolation: the product zone is read-only for ordinary "
            "users, each person writes only to their own work area, and personal directories are "
            "strictly isolated. You know that 'failure' has two meanings -- a slipped finger, and "
            "an attempt to exceed one's rights."
        ),
        tools=[CREW_TOOL_BY_NAME["check_policy"], CREW_TOOL_BY_NAME["get_policy_summary"]],
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )

    writer = Agent(
        role="Security Report Writer",
        goal="Turn the previous two stages into a deliverable Markdown report",
        backstory=(
            "Your readers are on-call engineers and the security lead: lead with the conclusion, keep "
            "every claim traceable, and make sure each statement can be pointed back to a specific "
            "audit record."
        ),
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )

    t1 = Task(
        description=(
            f"The audit log is at {log_path}.\n"
            "1) Call summarize_events for totals, failure count, and the operation/actor breakdown;\n"
            "2) Call group_by_actor for the per-actor failure aggregation;\n"
            "3) Call list_failures to sample the most recent failures.\n"
            "Output a purely factual summary (draw no conclusions) and label every number with the "
            "tool it came from."
        ),
        expected_output="Factual summary: totals / failures / distribution / per-actor aggregation / recent failure samples",
        agent=summarizer,
    )

    t2 = Task(
        description=(
            "Working from the factual summary above:\n"
            "1) Call get_policy_summary to retrieve the policy baseline;\n"
            "2) For every (zone, operation) pair that appears among the failures, call check_policy "
            "to verify it against the policy;\n"
            "3) Decide which failures are **clear violations of privilege** (for example a non-admin "
            "doing modify/delete in the product zone) and which are only **mis-clicks or missing "
            "permissions**;\n"
            "4) Rank the actors by risk and explain the ranking criteria.\n"
            "Never invent anything: every finding must cite its evidence (actor, operation, path, count)."
        ),
        expected_output="List of suspicious behaviour (with evidence) + risk ranking + justification",
        agent=analyst,
        context=[t1],
    )

    t3 = Task(
        description=(
            "Write the previous two stages up as a Markdown report with this structure:\n"
            "1. Executive summary (at most three points, conclusion first)\n"
            "2. Data overview (the numbers returned by the tools)\n"
            "3. Suspicious behaviour (actor / action / evidence / policy basis)\n"
            "4. Recommended actions (review / training / tighten policy)\n"
            "5. Appendix: which tools were used, over what data range, and the limitations\n"
            "The report must state explicitly that it is based on synthetic data and is a process "
            "prototype."
        ),
        expected_output="A complete Markdown report",
        agent=writer,
        context=[t1, t2],
    )

    return Crew(agents=[summarizer, analyst, writer], tasks=[t1, t2, t3], process=Process.sequential, verbose=True)
