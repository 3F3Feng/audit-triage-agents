> **Captured sample.** One end-to-end run (2026-09-20, commit after `e0cdad5`): `npm run dev -- triage`
> against the FastAPI service, crew on `deepseek-flash`, `TYPESAFE_API_KEY` set so the policy analyst
> also called `assess_actor_intent` (Jev). Data: `python data/generate_sample_logs.py` (seed 42, 400
> events). The crew took 100s; the same actor ranking from `GET /actors/assessment` alone took 1.1s.
> Model output varies run to run; the tool figures do not. §3.3 is where the crew reconciles Jev's
> typed judgments against the deterministic counts.
>
> The "degenerate Total column" the crew flags in §2.2 (and limitation 4) was a real `group_by_actor`
> bug, fixed right after this run: `total` now counts every event, and the tool prints the failure
> rate the crew had to derive by hand here (its derived rates match the fixed output exactly).

# Authorization-Failure Audit Review — sample_audit_logs.jsonl

> **This report is based on synthetic data and is a process prototype.** The audit file
> `data/sample_audit_logs.jsonl` is machine-generated
> sample data; all actor names, roles, paths and show titles are synthetic. No statement in this document
> is a finding about a real person, a real production system, or a real access-control decision. The
> purpose of the exercise is to demonstrate an auditable review *process*: tool outputs in, traceable
> conclusions out. Every figure below is labeled with the tool that produced it, and every claim in
> §3 is anchored to a specific audit record (actor + timestamp + operation + path).

---

## 1. Executive summary

1. **Conclusion: the failure volume is real but concentrated, and exactly one actor warrants immediate escalation.**
   Of 400 events in the window, 72 failed (18.0%, `summarize_events`). The deterministic classifier
   resolved those 72 into **49 policy violations and 23 permission errors** (`classify_failures`).
   A single contractor identity, **`temp_contractor`, accounts for 25 of the 49 violations** — 74% of his
   own failures — and is the **only actor in the log observed attempting every admin-only primitive**
   (`chown`, `chmod`, `product` modify and delete) *and* writing into another user's profile. Recommended:
   escalate now.

2. **The second finding is a negative one, and it matters: two of the seven actors are better explained by
   broken tooling than by intent.** `m.philip` (coordinator) has 9 failures of which **5 are permission
   errors** — operations the policy actually *permits* (44% violation rate) — and `r.novak`
   (pipeline_admin) has 3 of 4. The advisory intent model (`assess_actor_intent`, Jev) nevertheless labeled
   **all seven actors "probing"**, including these two with the lowest violation rates and the lowest
   probing confidence (p=0.79 for `m.philip`). On the deterministic counts, these two should be triaged as
   *review the automation*, not *discipline the person*.

3. **The single clearest control gap to tighten is `chown`.** `get_policy_summary` (policy v1.0) makes
   `chown` admin-only in **all three** zones — `product`, `work` and `user_profile`. Non-admin actors
   attempted it **8 times inside the 49-violation set** (`temp_contractor` 5, `h.cassidy` 2, `a.chen` 1),
   including three attempts on the actor's *own* directory where ownership is not in question. That makes it
   the most repeated admin-only-primitive attempt in the log and the strongest evidence of deliberate
   probing rather than mis-click.

---

## 2. Data overview

### 2.1 Overall scale — source: `summarize_events`

| Metric | Value |
|---|---|
| Total events | 400 |
| Failures | 72 |
| Failure rate | 18.0% |
| Window start | 2026-09-20T18:43:43.031546Z |
| Window end | 2026-09-21T02:42:31.031546Z |

**Operation breakdown — source: `summarize_events`**

| Operation | Count |
|---|---|
| create | 174 |
| mkdir | 122 |
| modify | 47 |
| delete | 28 |
| chmod | 19 |
| chown | 10 |

**Busiest actors — source: `summarize_events`** (top_n=10 was requested; the tool returned 7 rows)

| Actor | Events |
|---|---|
| temp_contractor | 144 |
| r.novak | 49 |
| j.goran | 46 |
| h.cassidy | 45 |
| d.olivares | 44 |
| m.philip | 39 |
| a.chen | 33 |

The seven returned rows sum to **400**, i.e. they appear to account for every event in the file; on that
reading the tool returned all distinct actors rather than truncating at 7. *(This is this report's
arithmetic inference from `summarize_events`, not a tool assertion.)*

### 2.2 Per-actor failure aggregation — source: `group_by_actor` (only_failures=true)

| Actor | Role | Failures / Total¹ | Zones (zone: count) | Ops (op: count) |
|---|---|---|---|---|
| temp_contractor | contractor | 34 / 34 | user_profile: 5, product: 20, work: 9 | modify: 11, create: 6, chown: 5 |
| m.philip | coordinator | 9 / 9 | work: 4, product: 4, user_profile: 1 | create: 6, delete: 2, mkdir: 1 |
| a.chen | artist | 7 / 7 | work: 6, user_profile: 1 | mkdir: 5, chown: 1, modify: 1 |
| h.cassidy | lighting_td | 7 / 7 | product: 2, work: 5 | create: 3, chown: 2, mkdir: 1 |
| d.olivares | artist | 6 / 6 | product: 3, user_profile: 1, work: 2 | delete: 2, mkdir: 2, create: 1 |
| j.goran | artist | 5 / 5 | product: 1, work: 4 | create: 4, chmod: 1 |
| r.novak | pipeline_admin | 4 / 4 | work: 3, product: 1 | modify: 2, create: 1, mkdir: 1 |

The failure column sums to 34 + 9 + 7 + 7 + 6 + 5 + 4 = **72**, which equals the failure count reported by
`summarize_events`. The two tools reconcile.

> ¹ **Ambiguity flag.** The "Total" column is **degenerate**: it equals the failure count in every single
> row. It therefore cannot be read as "failures out of that actor's total events" — `summarize_events`
> reports 144 events for `temp_contractor` alone, so "34 / 34" cannot mean 34 failures out of 34 events.
> No per-actor *event* denominator is available from these two tool calls. Use the counts in the
> `summarize_events` table (§2.1) if a per-actor denominator is needed.

**Derived per-actor failure rate** — computed by this report from §2.1 ÷ §2.2; **not** a direct tool output,
and subject to the ambiguity above:

| Actor | Failures | Events (`summarize_events`) | Derived failure rate |
|---|---|---|---|
| temp_contractor | 34 | 144 | 23.6% |
| m.philip | 9 | 39 | 23.1% |
| a.chen | 7 | 33 | 21.2% |
| h.cassidy | 7 | 45 | 15.6% |
| d.olivares | 6 | 44 | 13.6% |
| j.goran | 5 | 46 | 10.9% |
| r.novak | 4 | 49 | 8.2% |

**Recent failure sample — source: `list_failures` (limit=10)**
Tool header: *"72 failed events in total, showing the most recent 10:"*

| # | Timestamp | Actor | Role | Op | Zone / ownership | Path | Reason |
|---|---|---|---|---|---|---|---|
| 1 | 2026-09-21T02:34:07.031546Z | temp_contractor | contractor | mkdir | user_profile non-owner | /studio/users/m.philip/profile | Caller does not own the target path |
| 2 | 2026-09-21T02:31:43.031546Z | m.philip | coordinator | create | user_profile non-owner | /studio/users/temp_contractor/profile | Caller does not own the target path |
| 3 | 2026-09-21T02:30:31.031546Z | j.goran | artist | create | work non-owner | /studio/design/devrnd/sequence/SHOWB/work/temp_contractor/scene | Caller does not own the target path |
| 4 | 2026-09-21T02:29:19.031546Z | temp_contractor | contractor | chown | work owner | /studio/film/devrnd/sequence/SHOWA/work/temp_contractor/scene | Operation chown in zone work requires an admin role |
| 5 | 2026-09-21T02:25:43.031546Z | temp_contractor | contractor | modify | product non-owner | /studio/television/SHOWC/product/v1/scene | Product area is read-only. Modifications and deletions are not allowed. |
| 6 | 2026-09-21T02:23:19.031546Z | temp_contractor | contractor | delete | product non-owner | /studio/television/SHOWC/product/v1/scene | Product area is read-only. Modifications and deletions are not allowed. |
| 7 | 2026-09-21T02:22:07.031546Z | temp_contractor | contractor | modify | work non-owner | /studio/television/devrnd/sequence/SHOWC/work/d.olivares/scene | Caller does not own the target path |
| 8 | 2026-09-21T02:13:43.031546Z | d.olivares | artist | mkdir | work non-owner | /studio/design/devrnd/sequence/SHOWB/work/j.goran/scene | Caller does not own the target path |
| 9 | 2026-09-21T02:12:31.031546Z | temp_contractor | contractor | modify | work non-owner | /studio/television/devrnd/sequence/SHOWA/work/d.olivares/scene | Caller does not own the target path |
| 10 | 2026-09-21T02:10:07.031546Z | m.philip | coordinator | delete | product non-owner | /studio/film/SHOWA/product/v1/scene | Product area is read-only. Modifications and deletions are not allowed. |

**Distinct reason strings in the 10-row sample — source: `list_failures`**
- "Caller does not own the target path" — rows 1, 2, 3, 7, 8, 9 (**6 of 10**)
- "Operation chown in zone work requires an admin role" — row 4 (**1 of 10**)
- "Product area is read-only. Modifications and deletions are not allowed." — rows 5, 6, 10 (**3 of 10**)

**All 10 sampled rows are VIOLATIONS** under the policy classification in §3.1. This is a 10-row sample of
72 failures and **must not** be read as "all 72 failures are violations" — 23 of the 72 are not.

### 2.3 Deterministic classification of all 72 failures — source: `classify_failures`

**total failures: 72 | violations: 49 | permission errors: 23** (49 + 23 = 72 ✔)

| Actor | Role | Failures | VIOLATIONS | PERMISSION_ERRORS | Violation rate¹ |
|---|---|---|---|---|---|
| temp_contractor | contractor | 34 | **25** | 9 | 74% |
| d.olivares | artist | 6 | **6** | 0 | **100%** |
| h.cassidy | lighting_td | 7 | **5** | 2 | 71% |
| a.chen | artist | 7 | **4** | 3 | 57% |
| m.philip | coordinator | 9 | **4** | 5 | 44% |
| j.goran | artist | 5 | **4** | 1 | 80% |
| r.novak | pipeline_admin | 4 | **1** | 3 | 25% |

Column sums: 25+6+5+4+4+4+1 = **49** violations; 9+0+2+3+5+1+3 = **23** permission errors. The per-actor
failure totals (34+6+7+7+9+5+4 = 72) reconcile exactly with `group_by_actor` in §2.2.

> ¹ Violation rate = violations ÷ failures, computed by this report from `classify_failures` columns.

### 2.4 Policy baseline — source: `get_policy_summary`

**Policy version 1.0 — admin roles are `devops` and `pipeline_admin` and nobody else.** `coordinator` is
**not** an admin role.

| Zone | create | modify | delete | chmod | chown | mkdir |
|---|---|---|---|---|---|---|
| **product** (deliverable, immutable) | `*` | admin | admin | admin | admin | `*` |
| **work** (own directory only) | owner | owner | owner | owner | **admin** | owner, self_bootstrap |
| **user_profile** (strictly isolated) | owner | owner | owner | owner | **admin** | owner |

Policy notes carried verbatim from the tool: *"A non-admin performing modify/delete/chmod/chown in the
product zone is a clear policy violation, not a mis-click"*; work-zone `mkdir` allows `self_bootstrap`
(only one's **own** `work/<username>`); every failure must leave an audit record.

**Three classes, kept strictly separate throughout this report:**
- **VIOLATION** — the policy itself forbids the action (a genuine over-privilege attempt).
- **PERMISSION_ERROR** — the policy allows the action; it failed for another reason (e.g. POSIX bits). **Not**
  an over-privilege attempt.
- **Slip of the finger** — a permitted operation on the wrong path. Strictly a policy violation, but
  low-intent; flagged separately, never merged into the violation count.

### 2.5 Policy spot-checks — source: `check_policy` (role taken from each event's `actor_role`)

| Case (actor, role, op, zone, owner) | Policy verdict |
|---|---|
| temp_contractor, contractor, chown, work, **owner=True** | **DENY** — "chown in zone work requires an admin role (role=contractor, owner=True)" |
| m.philip, coordinator, delete, product, non-owner | **DENY** — "delete in zone product requires an admin role (role=coordinator)" |
| r.novak, pipeline_admin, mkdir, work, non-owner (`work/j.goran/scene`) | **DENY** — "mkdir in zone work may only bootstrap one's own directory (the path belongs to j.goran, the caller is r.novak)" |
| temp_contractor, contractor, mkdir, user_profile, non-owner | **DENY** — "mkdir in zone user_profile requires owner rights (role=contractor, owner=False)" |
| a.chen, artist, mkdir, work, non-owner (`work/h.cassidy/scene`) | **DENY** — only one's own directory may be bootstrapped |
| a.chen, artist, mkdir, work, **owner=True** (`work/a.chen`) | **ALLOW** — "the owner may mkdir in zone work" |
| temp_contractor, contractor, **create**, product, non-owner | **ALLOW** — "zone product permits create for all users" |
| temp_contractor, contractor, modify, work, **owner=True** | **ALLOW** — "the owner may modify in zone work" |
| r.novak, **pipeline_admin**, modify, product | **ALLOW** — "an admin role (pipeline_admin) may modify in zone product" |
| temp_contractor, contractor, chown, user_profile, **owner=True** | **DENY** — "chown in zone user_profile requires an admin role" |

Two things follow directly from this table. First, the violation verdicts in §3.1 are **policy-grounded**,
not eyeballed. Second, an **ALLOW-but-failed** path demonstrably exists (rows 7 and 8 above): product
`create` and owner-scoped work writes are permitted, so when they fail they are **PERMISSION_ERRORs**, not
violations. That is precisely the 23-error bucket in §2.3.

---

## 3. Suspicious behaviour

### 3.1 Actor-level evidence

The `classify_failures` violation list **enumerates all 49 violations** (25+6+5+4+4+4+1 = 49). The table
below gives, for each actor, the single most serious item from that enumeration and the policy rule it
breaks. **The timestamp + path + operation triple is the audit-record pointer**; any claim here can be
re-checked against that record in `sample_audit_logs.jsonl`.

| Actor (role) | Action | Evidence — audit record (timestamp / op / path) | Policy basis |
|---|---|---|---|
| **temp_contractor** (contractor) — 25 violations | Unauthorized modification and deletion inside an immutable deliverable, plus every admin-only primitive | `02:25:43 modify /studio/television/SHOWC/product/v1/scene`; `02:23:19 delete /studio/television/SHOWC/product/v1/scene`; `01:54:31 chmod /studio/film/SHOWC/product/v1/scene`; `22:25:43 chown /studio/television/SHOWA/product/v1/scene`; `02:34:07 mkdir /studio/users/m.philip/profile` | `product`: modify/delete/chmod/chown are **admin-only**; `check_policy` confirms DENY for a non-admin delete in product ("requires an admin role (role=coordinator)") and the policy states a non-admin modify/delete in product "is a clear policy violation, not a mis-click". `chmod`/`chown` are admin-only in all three zones. `user_profile` mkdir requires owner rights → DENY. |
| **d.olivares** (artist) — 6 violations, 0 permission errors | Cross-write into a colleague's work directory and into another user's profile | `02:13:43 mkdir /studio/design/devrnd/sequence/SHOWB/work/j.goran/scene`; `19:42:31 mkdir /studio/users/r.novak/profile`; plus `00:31:43 modify` and `20:37:43 delete` on product paths | `work` mkdir is `owner, self_bootstrap` — only one's **own** directory; `check_policy` confirms DENY for "a.chen … work/h.cassidy … may only bootstrap one's own directory". `user_profile` mkdir requires owner rights → DENY. Product modify/delete admin-only. |
| **h.cassidy** (lighting_td) — 5 violations | Uses the admin-only `chown` primitive twice, including on **his own** directory | `01:23:19 chown /studio/design/devrnd/sequence/SHOWC/work/h.cassidy/scene`; `21:54:31 chown /studio/film/devrnd/sequence/SHOWC/work/h.cassidy/scene`; plus `create`/`modify`/`mkdir` into `a.chen`'s and `d.olivares`' work dirs (`01:31:43`, `22:06:31`, `20:02:55`) | `work` `chown` is **admin**; lighting_td is not an admin. `check_policy` spot-check: "chown in zone work requires an admin role (role=contractor, owner=True)" → **DENY even though owner=True**, so ownership is no defence. |
| **j.goran** (artist) — 4 violations | Non-admin `chmod` on a product deliverable; repeated work-zone cross-creates | `19:31:43 chmod /studio/film/SHOWC/product/v1/scene`; `02:30:31 create /studio/design/devrnd/sequence/SHOWB/work/temp_contractor/scene`; `21:41:19` and `20:59:19` create into `a.chen`'s and `m.philip`'s work dirs | `product` `chmod` is **admin-only**; artists are not admins → VIOLATION. `work` create is `owner` → DENY for a non-owner path (matches `list_failures` row 3 reason "Caller does not own the target path"). |
| **a.chen** (artist) — 4 violations, 3 permission errors | `chown` attempt on a colleague's path; mkdir into three other users' work dirs | `21:43:43 chown /studio/television/devrnd/sequence/SHOWA/work/h.cassidy/scene`; `00:26:55`, `19:18:31`, `18:43:43 mkdir` into `h.cassidy`'s, `r.novak`'s and `temp_contractor`'s work dirs | `work` `chown` admin-only → DENY. `work` mkdir permits only `self_bootstrap` (own directory) → DENY. Note `check_policy` confirms **ALLOW** for "a.chen … mkdir … work … owner=True (`work/a.chen`)", i.e. the same operation is legal on his own path. |
| **m.philip** (coordinator) — 4 violations, **5 permission errors** | Two product `delete`s and a create into another user's profile — but the majority of failures are *permitted* operations | `02:31:43 create /studio/users/temp_contractor/profile`; `02:10:07 delete /studio/film/SHOWA/product/v1/scene`; `23:06:31 delete /studio/design/SHOWB/product/v1/scene` | `user_profile` create requires owner rights → DENY. `product` delete is admin-only; `coordinator` is **not** an admin role (`get_policy_summary`; `check_policy`: "delete in zone product requires an admin role (role=coordinator)") → VIOLATION. Separately, 5 of his 9 failures are ALLOW-but-failed → PERMISSION_ERROR. |
| **r.novak** (pipeline_admin) — 1 violation, 3 permission errors | One genuine boundary breach: work-zone `mkdir` into another user's directory | `22:19:43 mkdir /studio/design/devrnd/sequence/SHOWC/work/j.goran/scene` | `work` mkdir is `owner, self_bootstrap`; `check_policy` confirms **DENY** — "mkdir in zone work may only bootstrap one's own directory (the path belongs to j.goran, the caller is r.novak)". His product traffic is legal: `check_policy` returns **ALLOW** — "an admin role (pipeline_admin) may modify in zone product". |

### 3.2 Risk ranking (this report's ranking, criteria stated)

Criteria applied in order: (1) violation count; (2) violation *rate* (violations ÷ failures);
(3) operation sensitivity — `chown`/`chmod`/`delete` > `modify` > `create`/`mkdir`; (4) zone sensitivity
— `product` (immutable deliverable) > `user_profile` (isolated personal) > `work` (own dir);
(5) breadth across zones and operations; (6) admin-role amplification.

| Rank | Actor | Role | Viol. / Perm.err | Viol. rate | Rationale |
|---|---|---|---|---|---|
| **1** | temp_contractor | contractor | 25 / 9 | 74% | Highest volume *and* highest violation count; the only actor hitting every admin-only primitive (`chown`, `chmod`), product `delete`, *and* another user's profile. |
| **2** | d.olivares | artist | 6 / 0 | **100%** | Not one benign failure: 2 product deletes, 1 product modify, 1 `user_profile` breach, 2 work cross-writes. |
| **3** | h.cassidy | lighting_td | 5 / 2 | 71% | Two `chown` attempts on the admin-only primitive; persistent cross-writes into `a.chen`'s and `d.olivares`' work dirs. |
| **4** | a.chen | artist | 4 / 3 | 57% | 4 violations, but 3 of 7 failures are permission errors; lowest violation rate of the prober group. |
| **5** | j.goran | artist | 4 / 1 | 80% | A non-admin `chmod` on a product deliverable is a direct immutability attack; volume keeps him mid-table despite the higher rate. |
| **6** | m.philip | coordinator | 4 / 5 | 44% | Two product deletes are serious, but **more than half his failures are permitted operations** — the profile of misconfigured coordinator tooling. |
| **7** | r.novak | pipeline_admin | 1 / 3 | 25% | Only genuine violation is one work-zone bootstrap breach; his admin role makes most of his traffic legal, so the low count reflects policy, not restraint alone. |

### 3.3 Advisory intent model — source: `assess_actor_intent` (TypeSafe Jev)

| Actor | Role | fails / viol | Jev label | prob | concern (0–3) | Jev action |
|---|---|---|---|---|---|---|
| temp_contractor | contractor | 34 / 25 | **probing** | 0.95 (conf 0.95) | **2.66** (conf 0.66) | **escalate** |
| d.olivares | artist | 6 / 6 | probing | 0.96 (conf 0.93) | 2.13 (conf 0.78) | follow_up |
| m.philip | coordinator | 9 / 4 | probing | 0.79 (conf 0.72) | 1.91 (conf 0.72) | follow_up |
| h.cassidy | lighting_td | 7 / 5 | probing | 0.93 (conf 0.91) | 1.91 (conf 0.78) | follow_up |
| a.chen | artist | 7 / 4 | probing | 0.92 (conf 0.89) | 1.89 (conf 0.79) | follow_up |
| j.goran | artist | 5 / 4 | probing | 0.96 (conf 0.94) | 1.82 (conf 0.75) | follow_up |
| r.novak | pipeline_admin | 4 / 1 | probing | 0.86 (conf 0.81) | 1.59 (conf 0.47) | human_review |

Jev's implied order (most concerning first): temp_contractor 2.66 → d.olivares 2.13 → m.philip 1.91 →
h.cassidy 1.91 → a.chen 1.89 → j.goran 1.82 → r.novak 1.59.

**Agreements with §3.2.** temp_contractor is #1 in both, and Jev's strongest verdict (probing p=0.95,
concern 2.66, **escalate**) matches the strongest evidence. r.novak is last in both (concern 1.59,
`human_review`; §3.2 rank 7). h.cassidy and a.chen are adjacent mid-tier follow-ups in both.

**Disagreements, stated plainly.**
1. **m.philip is the biggest divergence** — Jev ranks him 3rd; §3.2 ranks him 6th. Reason: 5 of his 9
   failures are permission errors (44% violation rate, the lowest except r.novak). Jev itself flags this:
   his probing confidence (0.72) is the lowest of all seven. On this actor, **do not escalate** on Jev's
   score alone.
2. **Jev labels all seven actors "probing."** That over-calls: 23 of the 72 failures are *permitted*
   operations. Reserving the label for high violation rates would exclude m.philip (44%) and r.novak (25%),
   for which "misconfigured automation / unclear" fits the same evidence better.
3. **Jev's score compresses the top of the field.** d.olivares (100% violation rate) sits only 0.24 above
   m.philip (44%), because the concern score under-weights violation *rate* and over-weights raw failure
   count. §3.2's criteria 1–2 separate them.
4. **Minor:** §3.2 ranks j.goran (80% rate, product `chmod`) above a.chen (57% rate) on volume/sensitivity,
   while Jev places j.goran last among the six non-admin actors. A non-admin `chmod` on a product
   deliverable should not be discounted.

**Reconciliation rule applied in this report:** `classify_failures` is ground truth for *what happened*;
`assess_actor_intent` is advisory evidence for *why*, reported alongside. Where Jev's label contradicts the
counts — m.philip — **the counts win**, and this report says so rather than silently adopting Jev's order.

---

## 4. Recommended actions

### 4.1 Review (incident response)
- **Escalate now — `temp_contractor`** (25 violations; `chown`, `chmod`, product modify/delete, and an
  attempt on `m.philip`'s profile at `02:34:07`). Agrees with Jev's `escalate`. Pull the full event trail
  for this identity, not just the 10-row sample.
- **Investigate as probing — `d.olivares`** (6/6 violations, including two product deletes and a
  `user_profile` breach), **`h.cassidy`** (2× work `chown`), **`j.goran`** (product `chmod`).
- **Review as possible misconfigured automation, not malice — `m.philip`** (5 of 9 failures are permitted
  operations; check the coordinator's tooling and any service account behind it) and **`r.novak`** (3 of 4
  failures are permitted; his admin role makes most of his traffic legal). Confirm whether a shared
  automation job is producing these paths.
- **Watch — `a.chen`** (4 violations / 3 permission errors: mixed profile; the violations are work-zone
  boundary crossings plus one `chown`).

### 4.2 Training
- **Work-zone `self_bootstrap` is being misread as "any work directory."** Six of the ten sampled failures
  share the reason "Caller does not own the target path", and at least six distinct actors crossed a work
  or profile boundary. A short, targeted module on *own-directory-only* `mkdir`/`create`/`modify` is the
  highest-yield training item.
- **Admin-only primitives need an explicit callout.** `chown` is admin-only in all three zones and
  `chmod` is admin-only in `product`; both were attempted by non-admins. Train that ownership does not
  imply the right to change ownership (see the `check_policy` DENY with `owner=True`).
- **`coordinator` is not an admin role.** One product `delete` came from a coordinator. Make the role
  matrix from `get_policy_summary` part of onboarding rather than tribal knowledge.

### 4.3 Tighten policy / controls
- **`chown`: 8 non-admin attempts inside the 49-violation set** (`temp_contractor` 5, `h.cassidy` 2,
  `a.chen` 1), including three on the actor's own directory. This is the single most repeated admin-only
  primitive in the log. Tighten by alerting on *any* non-admin `chown` attempt rather than recording it as
  a routine failure.
- **`product` immutability:** consider a hard pre-execution block (not just a post-hoc DENY record) for
  non-admin `modify`/`delete`/`chmod`/`chown` in the `product` zone, backed by the policy's own statement
  that this "is a clear policy violation, not a mis-click".
- **Contractor scoping:** `temp_contractor` produced 144 of 400 events and 25 of 49 violations. Review
  whether contractor identities should be provisioned with a narrower initial role, and add a
  volume-plus-violation-rate trigger so a single identity cannot accumulate 34 failures unnoticed.
- **Permission-error noise:** 23 of 72 failures are permitted operations that failed — a signal about
  tooling or filesystem state, not about privilege. Separate those alerts from violation alerts so the
  violation queue is not diluted.

---

## 5. Appendix

### 5.1 Tools used, and what each contributed

| Tool | Role in this report | Output used |
|---|---|---|
| `summarize_events` | Scale, operation mix, busiest actors | 400 events / 72 failures / 18.0%; 6 operations; 7 actors |
| `group_by_actor` (`only_failures=true`) | Per-actor failure, zone and operation aggregation | 7 rows; failure column sums to 72 |
| `list_failures` (`limit=10`) | Most recent failures with reason strings | 10 of 72 rows; 3 distinct reason strings |
| `get_policy_summary` | Policy baseline | policy v1.0; admin roles `devops`, `pipeline_admin`; 3-zone permission matrix |
| `classify_failures` | **Ground truth** deterministic split | 72 → 49 violations / 23 permission errors; enumerated violation list |
| `check_policy` | Spot-checks that verdicts are policy-grounded | 10 cases (7 DENY, 3 ALLOW) |
| `assess_actor_intent` | Advisory intent model (Jev), reported alongside — never overriding the counts | 7 actors, all labeled "probing"; concern scores 1.59–2.66 |

### 5.2 Data range and scope

- **Source file:** `data/sample_audit_logs.jsonl`
- **Events:** 400; **failures:** 72; **window:** 2026-09-20T18:43:43.031546Z → 2026-09-21T02:42:31.031546Z
  (a single overnight run of roughly eight hours, per `summarize_events`).
- **Entities observed:** 7 actor identities, 3 zones (`product`, `work`, `user_profile`), 6 operations.
- **Policy version in force:** 1.0 (`get_policy_summary`).

### 5.3 Limitations

1. **Synthetic data; process prototype.** Nothing here is a finding about a real person or system. The
   deliverable is the *process*, not the conclusion.
2. **Sample coverage.** `list_failures` returned 10 of 72 failures; the reason-string distribution
   (6/1/3) describes only those 10 rows and was **not** extrapolated to all 72.
3. **All 10 sampled rows are violations**, which is consistent with — but does not prove — the 49/23 split.
   It must not be generalized to "all 72 failures are violations."
4. **Degenerate "Total" column.** In `group_by_actor`, Failures == Total for all seven actors, so the second
   column cannot be read as a per-actor event total. The derived failure rates in §2.2 are therefore
   computed against `summarize_events` counts and are marked as this report's arithmetic, not tool output.
5. **Actor-set assumption.** The busiest-actor rows sum to 400, which suggests the 7 returned actors are all
   actors; this report assumes the actor identities in `summarize_events` and `group_by_actor` correspond,
   since they were separate tool calls.
6. **Timestamp granularity.** Stage-2's enumerated violation list reported time-of-day only; full ISO
   timestamps are available for the §2.2 sample rows. Dates were not re-derived for the violation-only
   records.
7. **Intent labels are advisory and over-broad.** `assess_actor_intent` assigned the single label "probing"
   to all seven actors, including the two with the lowest violation rates. Where it contradicts
   `classify_failures`, this report followed the classifier and said so (§3.3).
8. **No baseline window.** A single ~8-hour slice cannot distinguish a first occurrence from an established
   pattern; there is no prior-period comparison.
9. **No re-derivation.** Violation/permission-error verdicts were taken from `classify_failures` and
   spot-checked with `check_policy`; this report did not independently re-parse the 49 enumerated records.
10. **Path-derived zoning.** Zone and ownership are inferred from path strings by the tools; this report
    relies on that parse and does not re-validate it.