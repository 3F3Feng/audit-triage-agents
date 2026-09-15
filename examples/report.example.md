# Audit Log Triage and Authorization Policy Report

**Synthetic-data prototype notice:** This report is based entirely on synthetic data and is a process prototype. It is not a production security determination, employment decision, or confirmed-incident report.

---

## 1. Executive summary

1. **Conclusion first:** The strongest signal is that three actors have documented attempts at admin-gated verbs in the immutable **product** zone: **temp_contractor** (`chmod` sample #9; `chown` sample #8), **m.philip** (`delete` sample #4), and **h.cassidy** (`chown` sample #10). Per `get_policy_summary` / `check_policy`, these are policy violations, not mere technical failures.
2. **Scale:** Across **400** synthetic events, **50** failed (**12.5%**). **temp_contractor** accounts for **23 of 50** failures and has the widest zone spread. In the **10 most recent** failures returned by `list_failures`, triage is **4 clear violations, 5 mis-clicks/missing permissions, 1 borderline**.
3. **Action:** Review **temp_contractor**, **m.philip**, and **h.cassidy**; reconcile the **product create/mkdir ALLOW-vs-denied mismatch** for temp_contractor; fix POSIX/group provisioning; tighten product-zone alerting and audit-reason clarity. Full evidence follows.

---

## 2. Data overview

### 2.1 Overall shape

**Source:** `summarize_events`

- **Total events:** 400
- **Failures:** 50 (12.5%)
- **Time range:** `2026-09-14T22:09:49.366696Z` → `2026-09-15T06:08:37.366696Z`

**Operation mix** — source: `summarize_events`

| Operation | Count |
|---|---:|
| create | 186 |
| mkdir | 109 |
| modify | 51 |
| delete | 24 |
| chmod | 18 |
| chown | 12 |

**Busiest actors, top 10 returned** — source: `summarize_events`

| Actor | Events |
|---|---:|
| temp_contractor | 134 |
| j.goran | 51 |
| m.philip | 50 |
| d.olivares | 46 |
| a.chen | 44 |
| r.novak | 44 |
| h.cassidy | 31 |

*The tool returned 7 actors total in this top-10 list. The sum of these actor counts is 400, matching the reported total.*

---

### 2.2 Per-actor aggregation

**Source:** `group_by_actor`

| Actor | Failures / Total | Zones touched | Ops breakdown |
|---|---:|---|---|
| temp_contractor | 23 / 134 | product: 51, work: 69, user_profile: 14 | create: 62, mkdir: 33, modify: 18 |
| m.philip | 10 / 50 | product: 16, work: 27, user_profile: 7 | create: 19, mkdir: 14, modify: 7 |
| a.chen | 7 / 44 | work: 23, product: 15, user_profile: 6 | create: 22, mkdir: 13, modify: 5 |
| d.olivares | 5 / 46 | product: 20, work: 23, user_profile: 3 | create: 20, mkdir: 16, modify: 7 |
| j.goran | 4 / 51 | product: 22, work: 23, user_profile: 6 | create: 30, mkdir: 9, modify: 7 |
| h.cassidy | 1 / 31 | product: 11, work: 19, user_profile: 1 | create: 12, mkdir: 10, modify: 3 |
| r.novak | 0 / 44 | work: 31, user_profile: 3, product: 10 | create: 21, mkdir: 14, modify: 4 |

Failures summed across actors — source: `group_by_actor`:  
23 + 10 + 7 + 5 + 4 + 1 + 0 = **50**, matching the failure count from `summarize_events`.

---

### 2.3 Recent failure sample and reason categories

**Source:** `list_failures`

- The tool reported **50 failed events in total** and returned the **most recent 10**.
- The detailed 10-row evidence with policy verdicts is shown in **§3.4**.
- Distinct failure reasons observed in the sample:
  - “Caller group not permitted for this zone”
  - “lack corresponding POSIX write permission bits on the file/folder”
  - “Caller does not own the target path”
  - “Path is outside the permitted zone for this caller”
  - “Product area is read-only. Modifications and deletions are not allowed.”

No conclusions are drawn in this data-overview section; all figures are attributed to the tool call that produced them.

---

## 3. Suspicious behaviour

### 3.1 Policy baseline

**Source:** `get_policy_summary`, policy v1.0

Admin roles: **devops**, **pipeline_admin**.

| Zone | create | mkdir | modify | delete | chmod | chown |
|---|---|---|---|---|---|---|
| **product** (delivery, immutable) | `*` | `*` | **admin** | **admin** | **admin** | **admin** |
| **work** (own dir only) | owner | owner, self_bootstrap | owner | owner | owner | **admin** |
| **user_profile** (isolated) | owner | owner | owner | owner | owner | **admin** |

Policy notes:

- A **non-admin performing modify/delete/chmod/chown in the product zone is a clear policy violation, not a mis-click.**
- `work` allows `self_bootstrap`: a user may create their **own** `work/<username>` directory.
- Every failure must leave an audit record.
- In the product zone, **create and mkdir are allowed to everyone**; only the four mutating/destructive verbs are admin-gated.

---

### 3.2 `check_policy` results for every (zone, operation) pair seen in failures

**Source:** `check_policy`

| Zone | Operation | is_admin | is_owner | Result | Reason |
|---|---|---|---|---|---|
| product | create | false | false | **ALLOW** | permits create for all users |
| product | mkdir | false | false | **ALLOW** | permits mkdir for all users |
| product | modify | false | false | **DENY** | requires the admin role |
| product | delete | false | false | **DENY** | requires the admin role |
| product | chmod | false | false | **DENY** | requires the admin role |
| product | chown | false | false | **DENY** | requires the admin role |
| work | create | false | true | ALLOW | owner may create |
| work | mkdir | false | true | ALLOW | owner may mkdir (self_bootstrap) |
| work | modify | false | true | ALLOW | owner may modify |
| work | delete | false | true | ALLOW | owner may delete |
| work | chmod | false | true | ALLOW | owner may chmod |
| work | chown | false | true | **DENY** | requires the admin role |
| work | create | false | false | **DENY** | requires owner rights |
| work | mkdir | false | false | ALLOW | permitted to bootstrap one’s own work dir |
| user_profile | create/modify/delete/chmod/mkdir | false | true | ALLOW | owner may operate in own profile |
| user_profile | chown | false | true | **DENY** | requires the admin role |

Every pair that appears among the failures has been checked against the live policy.

---

### 3.3 Failure-reason → policy mapping

| Audit reason string | What it means against policy | Category |
|---|---|---|
| “Product area is read-only. Modifications and deletions are not allowed.” | Matches the admin-gated verbs in product | **Violation** |
| “Path is outside the permitted zone for this caller” | Caller reaching into a zone they don’t belong to | **Violation** |
| “Caller does not own the target path” | Owner-only rule (work/user_profile) hit by a non-owner | Borderline / missing permission |
| “lack corresponding POSIX write permission bits on the file/folder” | A **filesystem** permission gap, not necessarily a policy gap — policy may still ALLOW | **Mis-click / missing permission** * |
| “Caller group not permitted for this zone” | Group-level provisioning gap; the op itself may be policy-ALLOW | **Mis-click / missing permission** |

\* Important trap: for an **admin-gated product verb**, the “POSIX bits” wording is only technical noise — the *operation* is the violation.

---

### 3.4 Documented suspicious events — actor / action / evidence / policy basis

**Source for events:** `list_failures`. **Source for verdicts:** `check_policy`.

| # | Actor | Action / Op | Zone | Path | Audit reason | Policy verdict | Triage |
|---:|---|---|---|---|---|---|---|
| 1 | temp_contractor | mkdir | product | `/studio/design/SHOWB/product/v1/scene` | Caller group not permitted | ALLOW (`mkdir→*`) | **Mis-click / missing perm** |
| 2 | temp_contractor | create | product | `/studio/television/SHOWA/product/v1/scene` | Caller group not permitted | ALLOW (`create→*`) | **Mis-click / missing perm** |
| 3 | m.philip | create | work | `/studio/television/devrnd/sequence/SHOWA/work/m.philip/scene` | lack POSIX write bits | ALLOW (owner) | **Mis-click / missing perm** |
| 4 | m.philip | delete | product | `/studio/film/SHOWA/product/v1/scene` | lack POSIX write bits | **DENY (admin only)** | **Clear violation** |
| 5 | temp_contractor | modify | work | `…/work/temp_contractor/scene` | lack POSIX write bits | ALLOW (owner) | **Mis-click / missing perm** |
| 6 | a.chen | mkdir | work | `/studio/design/devrnd/sequence/SHOWA/work/a.chen/scene` | Caller does not own target path | owner/self_bootstrap | **Borderline (owner mismatch)** |
| 7 | m.philip | delete | work | `…/work/m.philip/scene` | lack POSIX write bits | ALLOW (owner) | **Mis-click / missing perm** |
| 8 | temp_contractor | chown | product | `/studio/television/SHOWA/product/v1/scene` | Path outside permitted zone | **DENY (admin only)** | **Clear violation** |
| 9 | temp_contractor | chmod | product | `/studio/television/SHOWB/product/v1/scene` | Product area is read-only | **DENY (admin only)** | **Clear violation** |
| 10 | h.cassidy | chown | product | `/studio/design/SHOWB/product/v1/scene` | lack POSIX write bits | **DENY (admin only)** | **Clear violation** |

**Totals in the documented sample:** **4 clear violations, 5 mis-clicks/missing permissions, 1 borderline.**

---

### 3.5 Clear violations of privilege

These are non-admins invoking an **admin-gated verb** in the immutable **product** zone. Per policy notes, these are deliberate policy violations, not mis-clicks.

- **temp_contractor — `chmod` on product** `/studio/television/SHOWB/product/v1/scene`  
  - Evidence: sample **#9**  
  - Audit reason: “Product area is read-only. Modifications and deletions are not allowed.”  
  - Policy basis: product `chmod` requires **admin**.

- **temp_contractor — `chown` on product** `/studio/television/SHOWA/product/v1/scene`  
  - Evidence: sample **#8**  
  - Audit reason: “Path is outside the permitted zone for this caller”  
  - Policy basis: product `chown` requires **admin**.

- **m.philip — `delete` on product** `/studio/film/SHOWA/product/v1/scene`  
  - Evidence: sample **#4**  
  - Audit reason: “lack POSIX write bits”  
  - Policy basis: product `delete` requires **admin**. The reason text is misleading; the verb itself is admin-only.

- **h.cassidy — `chown` on product** `/studio/design/SHOWB/product/v1/scene`  
  - Evidence: sample **#10**  
  - Audit reason: “lack POSIX write bits”  
  - Policy basis: product `chown` requires **admin**.

Structural policy-level violations to watch wherever they occur:

- **`chown` in work / user_profile** — admin-only.
- **Non-owner writes in work/user_profile** — `DENY: requires owner rights`.

---

### 3.6 Mis-clicks / missing permissions

The caller attempted something the policy **would allow**, and it failed for environmental/technical reasons.

- **temp_contractor — `mkdir`/`create` in product** (samples **#1, #2**)  
  - Policy: `product create→*`, `product mkdir→*`.  
  - Denied by “Caller group not permitted for this zone.”  
  - Triage: **access-provisioning gap**, not a privilege breach. This is arguably a policy/tooling inconsistency because `check_policy` says ALLOW while the gateway denied.

- **m.philip — `create`/`delete` in own work dir** (samples **#3, #7**); **temp_contractor — `modify` in own work dir** (sample **#5**)  
  - All on the caller’s **own** path.  
  - Policy: ALLOW (owner).  
  - Failed only on “lack POSIX write permission bits” → **filesystem permissions**, not authorization.

- **a.chen — `mkdir` in work** (sample **#6**)  
  - Audit reason: “Caller does not own the target path.”  
  - `work mkdir` is allowed for owner/self_bootstrap.  
  - Triage: **borderline ownership mismatch**, most consistent with a path typo rather than an attempt to seize another user’s area. This is the one work-zone event worth a second look.

**Category counts (documented sample):** Clear violations = **4**; Mis-click/missing-permission = **5**; Borderline = **1**.

---

### 3.7 Risk ranking of actors

**Criteria, in priority order:**

1. **Severity of the verb attempted** — admin-gated verbs against the **immutable product zone** (`modify`/`delete`/`chmod`/`chown`) rank highest; owner-only violations next; policy-ALLOWED ops that failed technically rank lowest.
2. **Volume of failures** — more failed attempts = more probes/exposure.
3. **Breadth of zone access** — actors touching all three zones show wider reach.
4. **Ownership boundary crossing** — attempts to write outside one’s own directory.

| Rank | Actor | Failures / Total | Product-zone admin-verb violations (evidence) | Zones touched | Verdict |
|---:|---|---:|---|---|---|
| **1** | **temp_contractor** | **23 / 134** | **chmod (#9), chown (#8)** — both in product | product 51, work 69, user_profile 14 | Highest risk: most failures **and** two documented admin-only product violations; widest zone spread; recurring pattern (23 fails) |
| **2** | **m.philip** | **10 / 50** | **delete (#4)** — in product | product 16, work 27, user_profile 7 | Second-highest volume among violators; a destructive delete attempt on a deliverable |
| **3** | **h.cassidy** | 1 / 31 | **chown (#10)** — in product | product 11, work 19, user_profile 1 | Low volume but single severe event: admin-only chown on a deliverable (ownership change enables further tampering) |
| **4** | **a.chen** | 7 / 44 | none evidenced | work 23, product 15, user_profile 6 | Ownership-mismatch mkdir in work (#6) = borderline, not escalation; failures mostly missing-permission |
| **5** | **d.olivares** | 5 / 46 | none evidenced | product 20, work 23, user_profile 3 | No documented admin-verb violation; treated as mis-clicks pending detail |
| **6** | **j.goran** | 4 / 51 | none evidenced | product 22, work 23, user_profile 6 | Lowest failure count among non-clean actors |
| **7** | **r.novak** | **0 / 44** | none | work 31, user_profile 3, product 10 | **Lowest risk**: zero failures across all zones |

**Justification for the ordering:**

- Ranks **1–3** are separated from **4–7** by a hard boundary: they **each have at least one documented attempt at an admin-gated verb in the immutable product zone**, which the policy explicitly calls a violation “not a mis-click.”
- **temp_contractor** (rank 1) outranks **m.philip** (rank 2) because it combines the **largest failure volume (23)** with **two** such violations and the **widest zone footprint**; it is a repeat offender, not a one-off.
- **m.philip** (rank 2) is above **h.cassidy** (rank 3) on **volume** (10 vs 1) and on the destructive nature of `delete`; **h.cassidy** sits at rank 3 purely on **severity-per-event** (a product `chown`), which outweighs a.chen’s seven low-severity mis-clicks.
- Ranks **4–6** have **no evidenced privilege violation** in the product zone; their failures match “missing POSIX bits / group not permitted / ownership mismatch,” i.e., the failure mode of an authorized user who simply lacks a bit or fat-fingered a path. **a.chen** leads this group only because of the single borderline `work mkdir` ownership mismatch.
- **r.novak** (rank 7) is clean: **0/44 failures** is the strongest low-risk signal in the dataset.

---

## 4. Recommended actions

### 4.1 Review

- **Immediate review: temp_contractor, m.philip, h.cassidy.**  
  - Evidence: documented admin-gated product-zone attempts in samples **#8, #9, #4, #10**.  
  - Confirm intent, contractor scope, group membership, and whether any successful product-zone mutation occurred outside this sample.

- **Review temp_contractor’s product `create`/`mkdir` denials** (samples **#1, #2**).  
  - `check_policy` returns ALLOW for `product create` and `product mkdir`, but the gateway denied with “Caller group not permitted.”  
  - This is a **group-provisioning / policy-enforcement mismatch**, not a privilege violation by the actor, but it should be reconciled urgently because it creates noisy failures and masks real violations.

- **Review a.chen’s work-zone ownership mismatch** (sample **#6**) as a possible path typo or self-bootstrap edge case.

### 4.2 Training

- Train all studio actors on the **product zone rule**: `create`/`mkdir` are broadly allowed, but **`modify`, `delete`, `chmod`, and `chown` are admin-only**. A non-admin attempt is a policy violation, not a mis-click.
- Clarify **work-zone ownership** and `self_bootstrap`: users may create their own `work/<username>` directory, but cannot act on another user’s path.
- Explain that “lack POSIX write permission bits” may be technical noise on top of a policy-denied operation. Analysts and actors should not treat that reason string as proof the action was allowed.

### 4.3 Tighten policy / controls

- **Tighten product-zone alerting:** page or ticket on any non-admin `modify`/`delete`/`chmod`/`chown` attempt in product, regardless of audit reason string.
- **Separate audit reason categories:** distinguish *policy deny* from *filesystem/POSIX deny* from *group-provisioning deny*. This would prevent violations like sample **#4** and **#10** from being misread as mere permission-bit failures.
- **Fix POSIX/group provisioning:** reduce the false failures from “lack POSIX write bits” and “Caller group not permitted” where policy would allow the operation.
- **Verify every failure leaves an audit record** as required by policy.
- **Consider a stricter product create/mkdir decision** or update the gateway so its behavior matches `check_policy`. Current mismatch is a control gap: the policy says `*`, but the gateway denies.

### 4.4 Process / prototype improvements

- Re-run triage on the **full 50-failure set**, not only the 10 most recent returned by `list_failures`.
- Extend `group_by_actor` or add a new tool to return **per-actor, per-operation failure counts**, because the current aggregation gives op mix totals, not per-op failure counts.
- Add a sampling or export step that preserves all 50 failed events for human review.

---

## 5. Appendix

### 5.1 Tools used

| Tool | Purpose |
|---|---|
| `summarize_events` | Total events, failures, time range, operation mix, busiest actors |
| `group_by_actor` | Per-actor failures/total, zones touched, operation totals |
| `list_failures` | Reported 50 failures total; returned 10 most recent failure records |
| `get_policy_summary` | Policy v1.0 baseline: roles, zones, allowed operations |
| `check_policy` | Verdicts for each (zone, operation) pair seen among failures |

### 5.2 Data range and source

- **Source file:** `data/sample_audit_logs.jsonl`
- **Time range:** `2026-09-14T22:09:49.366696Z` → `2026-09-15T06:08:37.366696Z`
- **Total events:** 400
- **Failures:** 50 (12.5%)

### 5.3 Limitations

- **Synthetic data and process prototype.** This report is not a production incident report. Actor names are synthetic labels.
- **Sample limitation:** `list_failures` returned only the **10 most recent** of **50** failures. Therefore the “4 clear / 5 mis-click / 1 borderline” split is exact **for the documented sample**, not necessarily for all 50 failures.
- **Aggregation limitation:** `group_by_actor` gives **op mix totals, not per-op failure counts**. The per-actor risk ranking uses the documented sample plus aggregate totals and does **not** invent per-actor violation counts beyond what the sample shows.
- **Reason-text caveat:** “lack corresponding POSIX write permission bits” appears on genuine violations (**#4, #10**). Analysts must judge by the **operation vs the zone policy**, not by the audit reason string alone.
- **Flagged inconsistency, not an actor finding:** temp_contractor’s product `create`/`mkdir` denials (**#1, #2**) contradict `check_policy` returning ALLOW for `product create`/`mkdir`. This is a group-provisioning / policy-enforcement mismatch worth configuration review.
- **No intent determination:** this report identifies policy violations and suspicious patterns; it does not establish motive or actual data exfiltration/damage.
- **Traceability:** all actor/failure counts are from `group_by_actor`; zone/op totals from `summarize_events`; detailed events from `list_failures`; policy text from `get_policy_summary`; verdicts from `check_policy`.