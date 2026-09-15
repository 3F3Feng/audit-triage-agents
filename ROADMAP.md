# Dev plan

One main line, chosen for what it teaches about **software architecture**: turning the crew's
execution from an opaque synchronous call into an explicit, checkpointed, resumable — eventually
durable — execution model. Each stage is a self-contained step that stands on its own and sets up
the next. This is a learning/portfolio project, so "done" means *demonstrated and tested*, not
production-hardened.

The tool layer and the shared policy engine (`tools/`) don't change through any of this — every
stage is a change to the **orchestration layer**. That separation is the point: the deterministic
core stays put while the execution model around it gets more sophisticated.

**Baseline (today).** `POST /triage` runs a CrewAI `Process.sequential` crew synchronously and
holds the HTTP connection for ~60–90s. The three roles (summarize → analyze → write) are a fixed,
opaque pipeline: no visible state, no resume, no per-step retry.

---

## Stage 1 — An async execution boundary

Stop holding the connection. Submit returns immediately; the result is fetched later.

- **API:** `POST /triage → 202 { job_id, status: "queued" }`; `GET /triage/{job_id} → { status:
  queued|running|done|error, report, stats, elapsed_seconds, error }`. The deterministic endpoints
  (`/health`, `/policies`, `/events/summary`) stay synchronous — they're already fast and LLM-free.
- **Build:** an in-process `asyncio` worker + an in-memory `dict[job_id, JobRecord]` store.
  `crew.kickoff()` is blocking and hits the network, so run it via `anyio.to_thread.run_sync`, never
  on the event loop. A `Semaphore` caps concurrent runs (and token spend). CLI `triage` submits then
  polls; `--no-wait` prints the `job_id` and exits.
- **Teaches:** the submit/poll boundary, a worker, an explicit job lifecycle
  (`queued → running → done/error`), and concurrency control.
- **Done when:** `POST /triage` returns in well under a second, the report is retrievable by
  `job_id`, and a stubbed-crew test (no model) exercises the lifecycle in CI.

## Stage 2 — Make the execution graph explicit (LangGraph)

Replace the opaque `Process.sequential` with an explicit state graph. This is the stage with the
highest architecture density: it forces state, nodes, and transitions to be written down.

- **Build:** model the run as a graph — `summarize → analyze → write` nodes over a single typed
  state object (`TypedDict`/pydantic) that each node reads and extends. Use LangGraph (or a small
  hand-rolled state machine). The agents and their prompts move onto the nodes; the tools they call
  are unchanged.
- **Teaches:** explicit state vs. hidden pipeline state, node/edge boundaries, and turning a black
  box into something you can print, export, and reason about.
- **Done when:** the execution graph can be rendered/exported, and each node's input and output
  state are inspectable in a run.

## Stage 3 — Checkpoint and resume

Add durability to the graph: persist state between nodes so a crashed or interrupted run continues
instead of starting over (and re-burning tokens).

- **Build:** attach a checkpointer (LangGraph's SQLite/Redis saver) that writes state after each
  node. On restart, resume from the last checkpoint. Add per-node retry with idempotency, and a
  human-in-the-loop `interrupt` between analyze and write (pause for review, then continue).
- **Teaches:** checkpointing, resume-after-crash, idempotency and retry semantics, and
  interrupt/continue — the core of durable execution, at the application layer.
- **Done when:** killing the process mid-run (say during `analyze`) and restarting resumes from the
  checkpoint rather than re-running earlier nodes; the finished report is unchanged.

## Stage 4 (optional) — Infrastructure-grade durable execution (Temporal)

The ceiling. Move execution onto Temporal to learn durable execution at the infrastructure layer
rather than the application layer.

- **Build:** split into workflow + activities, run a separate worker, lean on Temporal's
  deterministic replay and built-in retries/timeouts/heartbeats.
- **Teaches:** the difference between application-level checkpointing (Stage 3) and
  infrastructure-level durable execution — cross-process/cross-host replay and operability.
- **When it's worth it:** only once you want durability and retries to survive across machines. For
  this demo it's a reach goal, not a requirement.

---

## Cross-cutting: observability

Runs through every stage, not a stage of its own. CrewAI and LangGraph both emit OpenTelemetry —
wire an exporter and add per-node token/cost and latency metrics as the execution model grows, so
each stage is measurable, not just runnable.

## Side track (orthogonal to the main line)

Small, independent items; some get partly absorbed by the stages above (report persistence and
idempotency fall out of Stage 3's checkpoint store).

- **Tighten `self_bootstrap`** so a `work` `mkdir` is allowed only in *your own* directory — a
  one-line change in `tools/policy.py` plus a test row.
- **Auth on the service** — an API-key/bearer check on `/triage` and its status route.
- **Pin `requirements.txt`** (`pip freeze`) so a fresh clone is reproducible; unpinned drift is
  what caused the `deepseek-chat` / tool-adapter surprises.
