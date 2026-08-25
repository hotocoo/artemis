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

Provide fixtures (`samples/authorization-fixtures.example.json`) with test principals, objects, and expectations. Artemis verifies ONLY these explicit cases - it never guesses identifiers or credentials. Every confirmed access-control finding yields a machine-executable regression test.

## 3. Running assessments

`artemis assessment start --scope my-scope.json --json`

During a run: every request passes rate limiting, scope verdicts, pinned DNS connections, timeouts, response-size caps, and decompression limits. The emergency stop cancels scheduling immediately and is audited.

## 4. Reading results

- CLI: `artemis finding list|show`, `artemis asset list`, `artemis report generate`
- Console: `artemis-console` serves the operator UI on 127.0.0.1 only.
- Reports: JSON, CSV, Markdown, HTML, SARIF 2.1. Coverage states distinguish tested / not tested / inaccessible / inconclusive / confirmed / inferred - reports never claim an environment is secure because checks passed.

### Reviewing discovered assets

Every asset discovery and service observation lands in the inventory; both surfaces read the same persisted rows:

```
artemis asset list                          # everything discovered so far
artemis asset list --assessment ASSESSMENT_ID
artemis --json asset list                   # full records incl. per-service banners and TLS flags
```

The console **Inventory** page shows the same rows with an assessment filter. Out-of-scope discoveries are never hidden: they stay listed with an explicit **OUT OF SCOPE** marker (the CLI tags them `OUT-OF-SCOPE`) because "the scanner reached something it should not have" is a scope-definition defect you must see, not a row to lose. The inventory is read-only by design - corrections belong to the scope configuration and the next assessment, not to history.

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

## 5. Evidence, redaction, retention

Evidence is redacted at creation (Authorization/Cookie headers, tokens, keys; strict mode available). Each scope's own `evidenceRetentionDays` governs how long that scope's evidence survives; audit entries form a SHA-256 hash chain you can verify at any time.

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