#!/usr/bin/env node
/**
 * audit-triage CLI -- triggers the Python-side CrewAI triage service.
 *
 * Zero runtime dependencies: only Node's built-in fetch / parseArgs / fs.
 * The point of it: prove the agent flow has a real service boundary, rather than only being
 * runnable as `python run.py` on the same machine.
 */
import { parseArgs } from "node:util";
import { writeFile } from "node:fs/promises";
import { basename } from "node:path";

const DEFAULT_SERVER = process.env.TRIAGE_SERVER ?? "http://127.0.0.1:8000";

const c = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
};

type Stats = {
  events: number;
  failures: number;
  failure_rate: number;
  operations: Record<string, number>;
  zones: Record<string, number>;
  top_actors_by_failure: Record<string, number>;
  window: string[];
};

type TriageResponse = {
  report: string;
  elapsed_seconds: number;
  stats: Stats;
  report_path: string | null;
};

function die(msg: string, code = 1): never {
  console.error(`${c.red}✗ ${msg}${c.reset}`);
  process.exit(code);
}

async function request<T>(server: string, path: string, init?: RequestInit): Promise<T> {
  const url = `${server.replace(/\/+$/, "")}${path}`;
  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
      signal: AbortSignal.timeout(30 * 60 * 1000), // agents are slow; allow 30 minutes
    });
  } catch (err) {
    die(`cannot reach ${url} -- is the service running? (uvicorn server:app --port 8000)\n   ${String(err)}`);
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    die(`${res.status} ${res.statusText} @ ${path}\n   ${body.slice(0, 600)}`);
  }
  return (await res.json()) as T;
}

function pct(x: number): string {
  return `${(x * 100).toFixed(1)}%`;
}

function bar(ratio: number, width = 24): string {
  const filled = Math.round(Math.max(0, Math.min(1, ratio)) * width);
  return "█".repeat(filled) + c.dim + "░".repeat(width - filled) + c.reset;
}

function printStats(s: Stats): void {
  console.log(`${c.bold}Data overview${c.reset} ${c.dim}(from the deterministic tool layer, no LLM involved)${c.reset}`);
  console.log(`  events    ${s.events}`);
  console.log(
    `  failures  ${s.failures}  ${bar(s.failure_rate)}  ${c.yellow}${pct(s.failure_rate)}${c.reset}`,
  );
  if (s.window.length === 2) {
    console.log(`  window    ${s.window[0]} -> ${s.window[1]}`);
  }
  console.log(`\n${c.bold}Operations${c.reset}`);
  const maxOp = Math.max(...Object.values(s.operations), 1);
  for (const [op, n] of Object.entries(s.operations)) {
    console.log(`  ${op.padEnd(8)} ${String(n).padStart(5)}  ${bar(n / maxOp, 16)}`);
  }
  console.log(`\n${c.bold}Zones${c.reset}`);
  for (const [zone, n] of Object.entries(s.zones)) {
    console.log(`  ${zone.padEnd(14)} ${String(n).padStart(5)}`);
  }
  if (Object.keys(s.top_actors_by_failure).length > 0) {
    console.log(`\n${c.bold}Actors with the most failures${c.reset}`);
    for (const [actor, n] of Object.entries(s.top_actors_by_failure)) {
      console.log(`  ${actor.padEnd(18)} ${String(n).padStart(4)}`);
    }
  }
}

const HELP = `${c.bold}audit-triage${c.reset} -- drive the multi-agent audit-triage flow

${c.bold}Usage${c.reset}
  audit-triage <command> [options]

${c.bold}Commands${c.reset}
  health                     check the service and the model endpoint
  policies                   print the current authorization policy
  summary  [--logs <path>]   deterministic statistics only (no LLM, instant)
  triage   [--logs <path>]   run the full CrewAI flow and print the report
           [--out <file>]    also write a local copy of the report

${c.bold}Options${c.reset}
  --server <url>   service address (default $TRIAGE_SERVER or http://127.0.0.1:8000)
  --json           emit JSON (handy for pipelines and CI)
  -h, --help       show this help

${c.bold}Examples${c.reset}
  ${c.dim}$${c.reset} npm run dev -- health
  ${c.dim}$${c.reset} npm run dev -- summary --logs data/sample_audit_logs.jsonl
  ${c.dim}$${c.reset} npm run dev -- triage --out report.md
`;

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: {
      server: { type: "string" },
      logs: { type: "string" },
      out: { type: "string" },
      json: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });

  const server = values.server ?? DEFAULT_SERVER;
  const cmd = positionals[0];

  if (values.help || !cmd) {
    console.log(HELP);
    return cmd ? 0 : 1;
  }

  if (cmd === "health") {
    const h = await request<{ status: string; model: string; base_url: string }>(server, "/health");
    if (values.json) {
      console.log(JSON.stringify(h, null, 2));
      return 0;
    }
    console.log(`${c.green}✓${c.reset} service up  ${c.dim}${server}${c.reset}`);
    console.log(`  model     ${c.cyan}${h.model}${c.reset}`);
    console.log(`  endpoint  ${h.base_url}`);
    return 0;
  }

  if (cmd === "policies") {
    const p = await request<Record<string, unknown>>(server, "/policies");
    console.log(JSON.stringify(p, null, 2));
    return 0;
  }

  if (cmd === "summary") {
    const qs = values.logs ? `?logs=${encodeURIComponent(values.logs)}` : "";
    const s = await request<Stats>(server, `/events/summary${qs}`);
    if (values.json) {
      console.log(JSON.stringify(s, null, 2));
      return 0;
    }
    printStats(s);
    return 0;
  }

  if (cmd === "triage") {
    const logs = values.logs ?? "data/sample_audit_logs.jsonl";
    console.error(`${c.dim}-> submitting triage job: ${logs}${c.reset}`);
    console.error(`${c.dim}   (three agents work sequentially; a hosted model takes about a minute)${c.reset}`);
    const r = await request<TriageResponse>(server, "/triage", {
      method: "POST",
      body: JSON.stringify({ logs, write_report: true }),
    });

    if (values.json) {
      console.log(JSON.stringify(r, null, 2));
      return 0;
    }

    console.log(
      `\n${c.green}✓${c.reset} done in ${c.bold}${r.elapsed_seconds}s${c.reset}` +
        (r.report_path ? `  ${c.dim}server wrote ${r.report_path}${c.reset}` : ""),
    );
    console.log();
    printStats(r.stats);
    console.log(`\n${c.bold}──────────── report ────────────${c.reset}\n`);
    console.log(r.report);

    if (values.out) {
      await writeFile(values.out, r.report, "utf8");
      console.log(`\n${c.green}✓${c.reset} local copy written -> ${basename(values.out)}`);
    }
    return 0;
  }

  die(`unknown command: ${cmd} (try --help)`);
}

main()
  .then((code) => process.exit(code))
  .catch((err) => die(String(err)));
