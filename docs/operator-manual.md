# Artemis Operator Manual

## 0. Read this first

Artemis assesses targets **you are explicitly authorized to test**. Every assessment requires a scope file with a signed authorization statement, an explicit allowlist, and hard limits. Artemis refuses ambiguity anywhere in authorization.

## 1. Authoring a scope

Start from `samples/scope.example.json`. Required fields:

- `scopeId` / `assessmentId` - fresh GUIDs per scope/run.
- `operatorIdentity`, `organization`, `authorizationStatement` - who you are and your claim of authority.
- `targetType` - Localhost, PrivateIp, PrivateSubnet, Hostname, Domain, Url, LocalSourceRepository, LocalContainer, TestEnvironment.
- `allowlistedTargets` - exact hostnames, CIDRs, URLs, or paths. Single-label names are rejected unless the type is TestEnvironment.
- `excludedTargets` - always win over the allowlist.
- `permittedPorts` / `permittedProtocols` - nothing outside these is ever contacted.
- Rate, concurrency, runtime, and request caps - conservative defaults provided; configuration cannot raise engine hard caps.
- `allowedCategories`/`prohibitedCategories` - category policy; contradictions are rejected.

Validate before running anything:

`artemis scope validate --file my-scope.json`

For private-target scopes, DNS names must resolve INSIDE the configured networks or the run fails closed (DNS-rebinding defense). Redirects are re-authorized per hop; HTTPS-to-HTTP downgrades are always blocked.

## 2. Authorization testing (optional)

Provide fixtures (`samples/authorization-fixtures.example.json`) with test principals, objects, and expectations. Artemis verifies ONLY these explicit cases - it never guesses identifiers or credentials. Every violated expectation becomes an audited access-control finding, and that finding is captured as a **stored, machine-executable regression test** (default cadence: 7 days) at the end of the run - no separate step required.

## 3. Running assessments

`artemis assessment start --scope my-scope.json --json`

During a run: every request passes rate limiting, scope verdicts, pinned DNS connections, timeouts, response-size caps, and decompression limits. The emergency stop cancels scheduling immediately and is audited.

## 4. Reading results

- CLI: `artemis finding list|show`, `artemis asset list`, `artemis report generate`
- Console: `artemis-console` serves the operator UI on 127.0.0.1 only.
- Reports: JSON, CSV, Markdown, HTML, SARIF 2.1. Coverage states distinguish tested / not tested / inaccessible / inconclusive / confirmed / inferred - reports never claim an environment is secure because checks passed.

### Generating reports

Reports assemble strictly from persisted rows and render deterministically per format:

```
artemis report generate --assessment ASSESSMENT_ID --format sarif --out ./reports
```

The console **Reports** page offers the same five formats (JSON, CSV, Markdown, HTML, SARIF) as one-click downloads for every stored assessment. Every generation - CLI or console - appends an audited `report.generated` entry to the hash chain, so the artifact trail is on the ledger next to everything else it summarizes. Generation fails closed when the assessment or its stored scope is missing: a report that cannot honestly describe its own scope is never produced.

### Reviewing discovered assets

Every asset discovery and service observation lands in the inventory; both surfaces read the same persisted rows:

```
artemis asset list                          # everything discovered so far
artemis asset list --assessment ASSESSMENT_ID
artemis --json asset list                   # full records incl. per-service banners and TLS flags
```

The console **Inventory** page shows the same rows with an assessment filter. Out-of-scope discoveries are never hidden: they stay listed with an explicit **OUT OF SCOPE** marker (the CLI tags them `OUT-OF-SCOPE`) because "the scanner reached something it should not have" is a scope-definition defect you must see, not a row to lose. The inventory is read-only by design - corrections belong to the scope configuration and the next assessment, not to history.

### The check execution ledger (coverage)

Every check outcome - completed, skipped, failed closed, timed out - is recorded as it happened.
That ledger is the only source of coverage truth:

```
artemis coverage show --assessment ASSESSMENT_ID [--json]
```

The output lists every recorded run with its true outcome and request footprint, honest verification
counts derived from those rows only (**tested** = executions that examined targets; **not tested** =
runs skipped before touching anything; **inaccessible** = timeouts; **inconclusive** = fail-closed
containment), plus the **persisted planning decisions** that say why a check was kept out of the
execution plan, and every registered check still **with no recorded execution and no stored reason**.
The engine records each planning exclusion BEFORE any work runs, so a missing check is either
explained by a stored decision or shown as an explicit gap - never papered over with a guess
(assessments recorded before this ledger existed have no rows, and the surfaces say so). An
assessment that executed nothing shows zeros everywhere, never a quiet "fully covered".

The console **Coverage** page drives the same read per assessment. Every generated report (JSON /
CSV / Markdown / HTML / SARIF, from either surface) computes its coverage section from this same
ledger, so a report can never claim more testing than was actually recorded.

### Triaging findings

Triage is an explicit, audited operator decision - the engine never invents one:

```
artemis finding triage FINDING_ID --status Confirmed --note "verified against lab" --actor alice
artemis finding triage FINDING_ID --status FalsePositive --note "test data, not a leak"
```

The lifecycle is deterministic and enforced fail-closed on both surfaces (CLI and console):

- **New / Reopened** may become Confirmed, AcceptedRisk, FalsePositive, or Remediated.
- **Confirmed** may become Remediated, AcceptedRisk, or FalsePositive.
- **Regressed** (a remediated finding re-detected by later runs) may be re-Confirmed or closed again.
- Terminal decisions (**Remediated**, **AcceptedRisk**, **FalsePositive**) survive every
  reobservation and open onto exactly one edge: explicit **Reopened**, so reversing a verdict is
  always deliberate.

Every decision records who decided, when, and why (note) directly on the finding row, plus a
tamper-evident `finding.triaged` entry in the hash-chained audit log next to the original
observation events. Illegal transitions, no-op repeats, and unknown findings are refused with the
list of allowed targets rather than silently accepted. On the console, the finding detail page
offers only the transitions the lifecycle allows from the current status.

### Baselines and drift

A security baseline freezes one assessment's observed state: every service seen, plus only those
finding fingerprints an operator has already dispositioned through triage (**AcceptedRisk** /
**FalsePositive**). It can never silently bless open issues - untriaged findings keep surfacing as
new drift until someone triages them and re-creates the baseline.

```
artemis baseline create --assessment ASSESSMENT_ID [--name NAME] [--actor OPERATOR]
artemis baseline list --scope SCOPE_ID            # or: --assessment ASSESSMENT_ID
artemis baseline compare --assessment ASSESSMENT_ID [--baseline BASELINE_ID]
```

Comparison runs one later assessment of the same scope against the stored snapshot and reports
two drift classes side by side:

- **Service drift** - a prohibited port answers (High) or an expected port went quiet (Medium).
- **Finding drift** - NEW findings at their own technical severity (never inflated or discounted),
  REGRESSED remediated issues detected again, and RESOLVED-or-unobserved accepted fingerprints at
  Informational - worded honestly, because absence alone cannot distinguish a real fix from checks
  that simply did not run this time.

The console **Baselines** page drives the same operations: create a baseline from any recent run,
then compare it against later runs with one click. Every create and compare lands in the
hash-chained audit log (`baseline.created`, `baseline.compared`).

`compare` is pipeline-friendly: exit code 0 when there is no drift, exit code 5 (gate failed)
when any observation exists - so scheduled assessments can fail loudly on change instead of
quietly collecting rows nobody reads.

### Regression verification

Every fixture-backed access-control finding keeps a durable promise: it will be re-verified.
Captured tests live in the database with their serialized replay recipe, a verification cadence,
and their complete run history:

```
artemis regression list [--assessment ASSESSMENT_ID]   # due state, cadence, last verdict per test
artemis regression show REGRESSION_TEST_ID             # replay steps, invariant, recent runs
artemis regression run --finding FINDING_ID --base-url URL [--fixtures FILE] [--cadence-days N]
```

- `run` stores (or refreshes) the test for that finding, executes the stored HTTP invariant through
  the safe engine against your explicitly supplied base URL, records the verdict, advances the
  cadence, and appends `regression.run_recorded` to the hash-chained audit log either way.
- A PASS is recorded honestly as "held"; a FAIL means **the original issue returned** - the run is
  recorded as a confirmation. It never silently flips the finding's triage status: status changes
  stay explicit operator decisions, but the evidence is on the ledger next to everything else.
- Only executable HTTP-expectation regressions are ever stored. Without fixtures describing real
  principals and objects, `regression run` refuses rather than persisting something it could not
  actually replay later.
- Disabling a test pauses its cadence without erasing the row or its history (`Pause` / `Resume` on
  the console page, audited as `regression.test_disabled` / `regression.test_enabled`).

The console **Regressions** page lists every stored test with its due state and last verdict;
due tests lead the list. Replays themselves always name their target explicitly via the CLI - a
countdown timer must never pick its own network destination.

## 5. Evidence, redaction, retention

Evidence is redacted at creation (Authorization/Cookie headers, tokens, keys; strict mode available). Each scope's own `evidenceRetentionDays` governs how long that scope's evidence survives; audit entries form a SHA-256 hash chain you can verify at any time.

### The audit ledger

Every lifecycle event - assessments, triage decisions, baselines, regressions, schedules,
retention sweeps, emergency stops, generated reports - lands in one hash-chained ledger. Each entry hashes the
previous entry's hash, so history cannot be rewritten without breaking every link that follows:

```
artemis audit verify            # walk the whole chain; exit 5 when it is broken
artemis audit list --action finding. --limit 20   # narrow by action prefix / correlation id
artemis audit export --format json --output ledger-archive.json   # complete ledger, oldest first
```

- **verify** reports the FIRST broken sequence and why: an edited payload fails its own content
  hash at that entry; a deleted or reordered row breaks the link at its successor; deleting the
  newest rows is exposed by the recorded chain head, which every append updates in the same
  transaction precisely so a shortened tail cannot masquerade as "nothing ever happened".
- **list** reads events newest-first with honest totals ("showing 20 of 412 stored event(s)");
  filters narrow, they never reorder or reinterpret. The console Audit page drives the same read
  with quick filters per event family.
- **export** archives the complete ledger chronologically as JSON or CSV (RFC 4180 quoting) for
  external auditors or compliance.

Keep at least one export outside the machine that runs Artemis. Hashes prove stored history was
not rewritten; they cannot by themselves prove rows were not deleted AND the chain head rewritten
to match - only comparison against an external archive exposes that. When verification does fail,
preserve the database as evidence: every finding, triage decision, and baseline derived from it is
now suspect.

Sweeping:

- `artemis retention status` - per-scope outlook: configured window, the cutoff it implies now, and how many evidence rows already outlived it.
- `artemis retention sweep --dry-run` - exactly what a sweep would remove, without removing it.
- `artemis retention sweep [--secure]` - removes every row strictly older than its scope's window in one transaction (evidence exactly at the boundary is retained), then appends an audited `evidence.retention_swept` event to the hash chain even when nothing was deleted. `--secure` additionally truncates the write-ahead log so freed pages stop surviving in sidecar journals.

While a console host or external ticks drive schedules, retention maintenance runs automatically - throttled to at most one automatic sweep per database per 24 hours, stamping its run without auditing quiet no-op passes. **Automatic sweeps are skipped outright while an emergency stop is armed** (in-process latch or persisted flag): an incident may be in progress and evidence must outlive it; they resume after disarming. Manual CLI sweeps are never throttled or blocked because explicit operator intent is their own authorization.

## 6. Advisory feeds

OSV integration ships disabled by default. When enabled, retrieved advisories carry retrieval time and staleness flags - stale data is labeled stale, never silently presented as current. Offline snapshots with optional SHA-256 pinning work fully air-gapped.


## 7. Scheduled assessments

Schedules re-run assessments automatically against a **frozen copy of a validated scope** - whatever passed structural validation at `add` time is exactly what runs later, revalidated before every fire. A schedule can never widen authorization.

```
artemis schedule add --name nightly-repo --scope my-scope.json --cron "0 3 * * *"
artemis schedule list          # shows last run and next local-time occurrence
artemis schedule disable SCHEDULE_ID
artemis schedule tick          # execute everything due right now
```

Execution model:

- The console host (`artemis-console`) ticks schedules automatically while it runs. Alternatively drive ticks from an external scheduler (cron, CI) via `artemis schedule tick`. **Use one ticker per database** - the console host OR external ticks, never both against one database, because due-selection reads `last_run_utc` without a distributed lease.
- Each fire is its own assessment (fresh assessment id, same scope id), so reports stay addressable per run while drift comparisons group by scope.
- While an emergency stop is armed, due schedules are skipped honestly (audited, left still due) and execute after disarming.
- Local repository scopes run the network-free source and dependency analyses; with no advisory feed configured, dependency severities are reported as **inconclusive**, never as clean.
- Every lifecycle event lands in the hash-chained audit log: created, enabled/disabled, run started/completed/failed, skipped for emergency stop.
- Ticks also carry throttled evidence-retention maintenance (section 5), skipped while an emergency stop is armed.

## 8. Emergency procedures

Console button or `artemis assessment stop --emergency`: arms the latch, cancels all in-flight cancellable work (engines poll the persisted flag every two seconds), and denies all new check execution until explicitly disarmed by an operator. The stop lives on two surfaces by design - the running host's in-process latch AND a persisted flag in the database - so a stop armed from one process is honored by every other process sharing that database.

Disarming is always an explicit, audited operator action; nothing disarms itself:

`artemis assessment disarm --reason "incident closed"`

or the **Disarm emergency stop** button on the console dashboard while a stop is armed. Disarm clears both surfaces, records who disarmed and why in the hash-chained audit log next to the original arm event, and fails closed if no stop is armed. While armed: new launches are refused before any work, due schedules are skipped honestly and remain due, automatic retention sweeps pause so evidence outlives the incident, and the dashboard banner names every surface still holding the stop.