# Changelog

All notable changes to Artemis are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The typed contracts in `src/ACT.Contracts` are the public API surface whose stability
a version bump commits to; the product version itself lives once in
`Directory.Build.props` and flows to the CLI, reports, and this file from there.

## [Unreleased]

## [1.1.0] - 2026-08-26

### Added

- **macOS and Linux release support** - the release pipeline now produces self-contained
  single-file executables for win-x64, linux-x64, linux-arm64, osx-arm64, and osx-x64 via the
  cross-platform `scripts/build-release.sh` (SHA-256 checksums, release manifest, and a
  CycloneDX SBOM per RID); CI runs the full test matrix natively on Ubuntu, macOS, and Windows,
  and the release workflow smoke-tests each natively published binary before packaging.
- Published-binary smoke coverage: the osx-arm64 artifact was exercised against a live loopback
  lab assessment and the linux-arm64 artifact inside a bare Debian container, both surfacing the
  persisted planning-exclusion ledger end to end.
- **Persisted planning-exclusion ledger (schema v4)** - the orchestrator's decision to keep a
  check out of an execution plan is now stored BEFORE any work runs (`plan.exclusions`, audited),
  so every coverage surface can answer "why did this registered check never record an execution?"
  from stored facts: `artemis coverage show` renders each persisted reason with occurrence counts,
  the console Coverage page shows the same decisions, and checks that still have no execution and
  no stored reason remain visible as an explicit gap instead of a mystery.
- **Benchmarks** for the planning-exclusion store at realistic scale (1,000 seeded decisions;
  filtered per-assessment listing and one typical 50-row save batch per iteration).

### Fixed

- **`artemis assessment start --scope FILE` works as documented, as a single command.** The launch
  path now registers the assessment row and its typed scope copy itself when no prior
  `assessment create` happened; previously such a run failed closed at its first lifecycle
  transition with a persistence error, and only the undocumented create-then-start sequence worked.
  Explicit pre-registration is unchanged and never duplicated.
- **Release directories are self-contained.** `build-release.sh` now stages each RID's published
  binaries into `artifacts/release/<rid>` before writing its metadata, so `release-manifest.json`,
  `SHA256SUMS`, and `sbom.json` sit next to the exact bytes they describe, `sha256sum -c` verifies
  in place, and the uploaded release artifact carries the executables instead of metadata alone.
  The release workflow verifies the checksums on a native runner before packaging.
- **One database-location rule for every surface.** The engine, `config show`, `scope list`,
  doctor, reports, and the console host now all resolve the database through the same shared
  helper: explicit configuration wins, otherwise the file lives beside the installed executable.
  Read surfaces previously anchored a relative path to the current directory while the engine
  anchored it to the install directory, so they could silently report on two different databases.
- The operator console publishes under its documented name: the self-contained single-file
  executable is now `artemis-console` (plus `artemis-console.exe` on Windows) instead of the raw
  assembly name `ACT.Desktop`, matching the operator manual and the release manifests.
- The benchmark entry point ignored command-line filters and always ran every benchmark in the
  assembly; it now routes arguments through BenchmarkSwitcher as documented.
- Formatting violations across several test files failed the CI format guard; corrected.

### Changed

- **Invariant globalization is enabled product-wide.** Every comparison and parse was already
  explicit Ordinal/InvariantCulture; freezing the culture removes host-locale variance from
  deterministic tooling and drops the ICU runtime dependency for self-contained Linux and macOS
  deployments.
- Linux deployments document OpenSSL 3 (`libssl3`) as their one native runtime dependency; the
  DNS-pinning gate's fail-closed refusal of out-of-scope resolutions was re-verified from inside
  a containerized network during cross-platform validation.
- `IAssessmentRecorder` gains `RecordPlanExclusionsAsync`; the engine persists planning decisions
  before executing any work item, exactly like the check-run ledger is recorded as work executes -
  together they leave no third state in which a check's absence from coverage is unexplainable.

## [1.0.0] - 2026-08-26

First stable release of the autonomous, local-first defensive security assessment
platform for explicitly authorized targets.

### Added

- **Scope authorization model** - signed authorization statement, allowlist/exclusions,
  permitted ports and protocols, category policy, rate/concurrency/runtime/request caps;
  deterministic fail-closed validator; DNS-pinning gate (resolution is never authorization);
  per-hop redirect re-authorization; HTTPS-to-HTTP downgrades always blocked.
- **Safe network engine** - token-bucket rate limiting, response-size and decompression-bomb
  defenses, pinned-DNS connections, timeouts, budget accounting.
- **Check suites** - TLS protocol/certificate/cipher checks, web security headers/cookies/CORS/
  cache checks, OpenAPI-driven API surface analysis, local source-code rule scanning,
  manifest-based dependency auditing with CycloneDX SBOM.
- **Assessment pipeline** - orchestrator with planning exclusions, finding deduplication on
  stable fingerprints, deterministic risk scoring, contained check failures.
- **Evidence handling** - redaction at creation (Authorization/Cookie headers, tokens, keys;
  strict mode), scope-configured retention windows, throttled automatic sweeps skipped while
  an emergency stop is armed, optional secure WAL truncation.
- **Persistence** - SQLite storage with ordered checksummed migrations; SHA-256 hash-chained
  audit ledger covering every lifecycle event.
- **Audit ledger read surface** - `artemis audit verify|list|export`: first-broken-link
  verification naming where tampering begins, filtered newest-first listing with honest totals,
  chronological JSON/CSV export for external auditors.
- **Finding triage lifecycle** - deterministic audited status transitions on both surfaces;
  terminal decisions survive reobservation and reopen only deliberately.
- **Asset inventory** - discovered assets and observed services, read-only by design,
  out-of-scope discoveries permanently visible and flagged.
- **Security baselines and drift** - snapshots accept only triage-dispositioned fingerprints;
  comparison reports service drift plus new/regressed/resolved findings at honest severities
  with a CI-friendly gate exit code.
- **Stored regression tests** - fixture-backed access-control findings captured as
  machine-executable HTTP invariants with verification cadence, verdict history, pause/resume;
  replays always name their target explicitly via the CLI.
- **Reports** - JSON / CSV / Markdown / HTML / SARIF 2.1 rendered deterministically from
  persisted rows only; every generation audited (`report.generated`); coverage claims derived
  strictly from the check execution ledger.
- **Check execution ledger** - every check outcome recorded as it happened;
  `artemis coverage show` and the console Coverage page surface honest verification counts
  (tested / not tested / inaccessible / inconclusive) plus registered checks with no recorded
  execution.
- **Scheduled assessments** - cron schedules run against a frozen validated scope copy,
  revalidated before every fire; due-selection skips honestly while an emergency stop is armed.
- **Emergency stop lifecycle** - two-surface stop (in-process latch + persisted flag) honored
  by every process sharing the database; disarm is explicit and audited; fails closed when
  nothing is armed.
- **Advisory feeds** - OSV integration disabled by default; retrieved advisories carry
  retrieval time and staleness flags; offline snapshots with optional SHA-256 pinning work
  fully air-gapped.
- **Operator console** - loopback-only web UI (dashboard, assessments, inventory, findings,
  coverage, reports, regressions, baselines, schedules, audit log, configuration, health)
  over the same engine and database as the CLI.
- **CLI** - 14-command surface (`config`, `scope`, `doctor`, `assessment`, `check`,
  `finding`, `coverage`, `audit`, `asset`, `baseline`, `report`, `regression`,
  `feed`, `schedule`, `retention`) with JSON output and fail-closed errors.
- **Quality gates** - unit (314 tests), integration/E2E against the loopback-only lab (12),
  adversarial safety (17) tiers plus benchmarks; analyzers on, warnings as errors.
- **Release pipeline** - win-x64 self-contained single-file publish, SHA-256 checksums,
  release manifest, SBOM, forbidden-marker scan, optional Authenticode signing with RFC 3161.

### Security

- Fail-closed posture throughout: ambiguous scope, malformed configuration, out-of-scope
  redirects, oversized responses, and policy violations abort instead of guessing.
- Explicit refusals honored: no credential theft, no malware, no destructive testing,
  no mass internet scanning; checks are passive or safe-request-only unless a scope and
  operator fixtures explicitly say otherwise.
- Reports never claim an environment is secure because checks passed; absence of findings
  is worded as absence of evidence.

### Known limitations (documented, by design)

- One schedule ticker per database: the console host OR external ticks, never both against
  one database (due-selection reads `last_run_utc` without a distributed lease).
- Audit hashes prove stored history was not rewritten; they cannot by themselves prove rows
  were not deleted AND the chain head rewritten - only comparison against an export kept
  off-machine exposes that.
- Coverage lists registered checks with no recorded execution but does not persist WHY a
  check was excluded at planning time.
- Without an advisory feed configured, dependency severities are reported as inconclusive,
  never as clean.
