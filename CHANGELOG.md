# Changelog

All notable changes to Artemis are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The typed contracts in `src/ACT.Contracts` are the public API surface whose stability
a version bump commits to; the product version itself lives once in
`Directory.Build.props` and flows to the CLI, reports, and this file from there.

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
