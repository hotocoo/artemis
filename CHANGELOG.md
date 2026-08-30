# Changelog

All notable changes to Artemis are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The typed contracts in `src/ACT.Contracts` are the public API surface whose stability
a version bump commits to; the product version itself lives once in
`Directory.Build.props` and flows to the CLI, reports, and this file from there.

## [0.1.5] - 2026-08-30

### Added

- **CMake/FetchContent dependency analysis.** Artemis now inventories CMake build manifests and
  flags supply-chain risks that have no canonical advisory feed: dependencies fetched over
  unencrypted http:// transport (High) and dependencies pinned to mutable branch references like
  master/main/develop (Medium). CMakeLists.txt files are recognized, and multi-line
  FetchContent_Declare and find_package declarations are parsed correctly.
- **Complete C++ exec-family command injection detection.** The SRC-INJECT-CMD-014 rule now covers
  the full exec family (execl, execlp, execle, execv, execve, execvp) in addition to system() and
  popen(), closing a gap where execve/execle calls were missed.

### Fixed

- **Command-injection rule no longer false-positives on English prose.** The SRC-INJECT-CMD-014
  pattern previously matched "system (" in comments and documentation (e.g. "rooster-tail system
  (the duplicate..."), producing false positives. The pattern now requires no whitespace between
  the function name and the opening parenthesis, matching only genuine C/C++ calls.

## [0.1.4] - 2026-08-29

### Added

- **C/C++ source analysis.** Artemis now detects native-code vulnerabilities: buffer-unsafe
  string/I-O functions (strcpy, strcat, sprintf), weak crypto primitives (MD5_Init, SHA1_Init,
  DES_set_key), and hard-coded secrets in C/C++ files. C++ projects (`.cpp`, `.cc`, `.h`, `.hpp`,
  `.c`) are now classified and scanned instead of skipped as Unknown.

### Fixed

- **Build and tool directories excluded from source scans.** CMake `build-*` trees, `_deps`,
  `.claude`/`.serena`/`.codegraph` worktrees, and other generated-output directories are now
  ignored, eliminating false positives from third-party build artifacts (previously a C++ repo
  scanned 2752 files, 2694 of them build output; now only first-party source is examined).
- **FindingDeduplicator is now thread-safe.** Parallel check execution could race on the shared
  deduplication dictionary, occasionally producing a FOREIGN KEY constraint failure when evidence
  referenced a finding not yet persisted. The merge/snapshot/contains paths are now gated by a lock.

## [0.1.3] - 2026-08-29

### Added

- **On-the-spot remediation: Artemis now fixes findings, not just reports them.** A new
  `artemis remediate` command and the `ACT.Remediation` engine close the find-and-fix loop that was
  the project's biggest capability gap. For each remediable finding (missing/misconfigured HSTS,
  CSP, and security headers; permissive or reflective CORS; insecure cookies; missing cache-control;
  plain-HTTP-without-HTTPS-redirect), the engine derives a concrete, machine-applicable plan and
  applies it through a local remediation proxy that corrects the target's live responses in place -
  injecting the missing headers, stripping wildcard CORS grants, hardening Set-Cookie attributes,
  or forcing the HTTP->HTTPS upgrade. Crucially, the fix is then VERIFIED by re-running the
  originating check: the outcome is only "Remediated" when the re-check against the corrected
  endpoint no longer reports the finding (e.g. CSP: 2 findings before -> 0 after). `artemis
  remediate --list` shows which stored findings are remediable. 14 new unit/live-loopback tests
  cover the planner and the apply-and-verify loop.

### Added (remediation extended to code and dependencies)

- **Remediation now reaches source-code and dependency findings, not just web responses.**
  - *Dependency remediation:* `artemis remediate FINDING_ID --repo PATH` upgrades the vulnerable
    package in its manifest to the advisory's fixed version - a surgical, single-package edit that
    preserves the rest of the file. Supports NuGet (.csproj), npm (package.json), PyPI
    (requirements.txt), and Cargo (Cargo.toml). Fails closed (no partial writes) when the package
    is absent or the manifest is unrecognized.
  - *Source remediation:* for rules with a safe, deterministic fix, the engine rewrites the
    offending code in place - weak crypto (MD5/SHA1/DES -> SHA-256/AES), disabled TLS validation
    (verify=False -> verify=True, rejectUnauthorized:false -> true), and insecure cookie flags
    (Secure/HttpOnly = false -> true). Rules without a provably-safe automatic fix (e.g. committed
    secrets, SQL injection) are honestly reported as guidance-only rather than rewritten blindly.
  - 9 new tests cover the manifest upgrader across all four ecosystems and the source fixer across
    the auto-fixable rules. End-to-end verified: a repo with `hashlib.md5` + `verify=False` was
    scanned (2 findings), remediated, and re-scanned (0 findings).

### Changed

- **Honest versioning.** Removed the premature 1.x release tags (v1.2.0, v1.1.0) that overclaimed
  production readiness. The project is now versioned 0.x to reflect that it is a pre-1.0 tool under
  active development. v0.1.2 is the current release.

## [1.2.0] - 2026-08-29

### Added

- **Bounded endpoint discovery for web-surface checks.** Header checks now discover a bounded set
  of same-origin paths from the landing page (href/src/action attributes, capped at 12) and probe
  each, so path-specific defects (permissive CORS on /api, missing HSTS on /login, insecure cookies
  on /session) are reported instead of only the root response. Out-of-scope or failing paths are
  skipped without aborting the check. This also fixed a latent DNS-gate bug: `ResolveVerifiedAsync`
  hardcoded port 80, so any non-default-port target failed closed on the first connect.
- **Playwright-driven e2e chaos workflow (e2e/).** Real built binaries (CLI, console, lab) on real
  loopback ports driven through a hostile operator lifecycle - 90 checks across 20 phases:
  happy-path assessment, fail-closed malformed scopes, out-of-scope redirects, emergency stops armed
  mid-flight from BOTH the CLI and the console, triage lifecycle through the rendered UI, concurrent
  assessments, baselines, all five report formats, audit-chain verification AND tamper detection,
  persistence across console restart, SIGKILL crash-recovery of stranded rows, port-conflict safety,
  honest empty-database states, authorization-fixture violations with regression capture/replay,
  HTTPS/TLS assessments against a self-signed origin, and scheduled-execution ticks. `bash
  e2e/run.sh` builds, installs Chromium, and runs the whole workflow with per-check results and
  screenshots; a CI job runs it on every push.
- **Crash recovery for stranded assessment rows.** A hard crash (kill -9, power loss) used to leave
  an assessment row in a non-terminal state forever, so surfaces would describe a run that is
  neither alive nor dead. Every host start now reconciles rows whose stored scope's MaxRuntime plus
  a grace window has fully elapsed since creation: they are marked Failed and audited as
  assessment.crash_reconciled. Fresh rows - including ones a live process started moments ago -
  are never touched, so two processes sharing one database never reconcile each other's live work.
- **The console's emergency stop is now global, matching the operator manual.** The console button
  previously armed only its own in-process latch, so a CLI-launched run kept contacting targets
  under an armed stop - the exact trap the documented contract forbids. The button now persists the
  same flag every process polls (audited as assessment.emergency_stop from operator-console)
  before arming the local latch; console disarm already cleared it.

- **The service-drift baseline scenario is live-proven end to end.** A real `ServiceDiscoveryCheck`
  observes real loopback services, a baseline is created and hardened through the new
  `artemis baseline prohibit` verb (`BaselineOperations.MarkProhibitedAsync`: supersedes any
  Expected entry for the port, idempotent, audited as `baseline.prohibited`), the environment then
  drifts - expected service dark, prohibited service alive - and comparison reports exactly the
  documented classes (expected-service-absent Medium, unexpected-service-exposed High, finding-new)
  with the CLI gate exiting 5. Until now `unexpected-service-exposed` existed as a kind code no
  production path could ever produce.
- **In-flight emergency-stop cancellation is live-proven at deterministic speed.** The persisted-flag
  watcher interval is operator-tunable via `Act:EmergencyStopWatch:PollInterval` (production default
  unchanged at two seconds), and an integration test drives the REAL launch path: assessment already
  executing, flag armed from "another process", watcher cancels mid-run, run recorded Stopped,
  no check completing after the stop, next launch denied pre-flight.
- **`artemis feed update` performs a real OSV liveness query** for enabled Osv sources through the
  production advisory client (one pinned single-package probe): success records the feed current;
  transport/HTTP/parse failures keep it stale with the specific reason attached. An opt-in test
  (`ARTEMIS_OSV_LIVE=1`) proves the same path against api.osv.dev.

### Fixed

- **`artemis assessment start` dumped a stack trace when the run was stopped.** An operator stop or
  runtime limit now prints a clear verdict (state recorded as Stopped, how to verify it) and exits
  with the runtime-failure code instead of an unhandled OperationCanceledException.
- **`artemis assessment status` failed with "database is not ready" on every launch.** It was the
  one command that read the database without initializing it first; every other read command owns
  its readiness, and status now does too.
- **Emergency-stop latch race that failed ubuntu CI.** Superseded token sources are now RETIRED
  instead of disposed eagerly: any handle ever handed out stays queryable until latch disposal, so a
  follower racing a disarm can read `Token`, register callbacks, or cancel without ever observing
  `ObjectDisposedException`. Post-dispose contract unchanged; concurrency hammer extended to 256
  iterations over token reads and registrations.
- **`EmergencyStopLatch.Disarm` never did what its comment claimed.** It disposed the only token
  source instead of swapping in a fresh one (leaving dead statements behind), exposed auto-properties
  `Reason`/`Actor` that were never assigned (snapshots always empty), and had no disposal path. All
  repaired with the same retirement semantics.
- **An emergency stop during a running assessment no longer strands it in Running.** The engine's
  cancellation catch required the cancellation NOT to come through the external token - but the
  emergency watcher cancels exactly that token, so the Stopped transition and `assessment.stopped`
  audit were skipped on precisely the path they exist for. Every cancellation route now records
  Stopped before rethrowing.
- **OSV default endpoint matched no implemented protocol.** Configuration shipped
  `https://api.osv.dev/v1/querybatch` while the provider posts the single-query body `/v1/query`
  defines - every enabled live query would have degraded to HTTP 400 stale forever.
- **The advisory client posted PascalCase bodies the real OSV API rejects.** `QueryBody`
  serialized with default options produced `{"Package":...}` members; api.osv.dev answers HTTP 400
  to unknown fields, so even on the correct path live queries failed forever - while body-agnostic
  loopback stubs stayed green. Query bodies now serialize with Web defaults (camelCase); the stub
  validates body shape and mirrors the real 400; the opt-in `ARTEMIS_OSV_LIVE=1` proof passes
  against production api.osv.dev.
- **Re-marking a prohibited port accumulated duplicate entries.** Prohibition now supersedes ANY
  prior entry for the port/protocol, not just Expected ones.

### Production verification

- **Release 1.2.0 verified production-live.** Full verification matrix executed against the real
  built binaries: Release build clean (0 warnings, 0 errors), 337 unit tests, 24 integration tests
  (real loopback lab fixtures), 17 safety tests (fail-closed invariants), and the 90-check Playwright
  e2e chaos workflow across 20 phases - hostile operator lifecycle, mid-flight emergency stops from
  both CLI and console, SIGKILL crash recovery, concurrent runs, audit-chain tamper detection,
  self-signed TLS, scheduled execution, and persistence across restarts - all passing. Self-contained
  single-file artifacts published for win-x64, osx-arm64, osx-x64, linux-x64, and linux-arm64 with
  in-place SHA256SUMS verification, CycloneDX SBOMs, and native execution of the shipped binaries.

## [1.1.1] - 2026-08-26

### Added

- **TLS handshake-inspection battery is wired into every URL assessment.** `ACT.Tls` shipped
  three checks - certificate trust/expiry (`ACT-TLS-CERT-001`), accepted protocol versions
  (`ACT-TLS-PROTOCOL-002`), and negotiated cipher suites (`ACT-TLS-CIPHER-003`) - but no
  composition path ever constructed them: they were unreachable dead weight behind the lab
  fixtures built to exercise them. URL launches now compose the trio through a dedicated
  handshake-only context on the same scope-validator/DNS-gate authorization path as the safe
  HTTP engine; http origins persist each member's `PROTOCOL_MISMATCH`, and assessing an https
  origin requires `"Tls"` among permitted protocols (sample scope and operator manual updated).
  Live lab proof: expired certificates surface as High findings, self-signed chains as Medium.

### Fixed

- **CLI diagnostics never touch stdout.** Engine log events were written to stdout, corrupting
  the `--json` output contract for any run whose checks logged while executing. The console
  logger now writes to stderr unconditionally; stdout carries command payloads only.
- **Natural TLS negotiation observes instead of aborting.** The probe's validation callback
  captured the chain but then returned false, so untrusted endpoints produced "handshake failed"
  warnings and the inspection checks could never see the certificate state they exist to report.
  After scope+DNS authorization, observation completes the handshake accept-only and records the
  chain errors alongside it.
- **Exclusion rows can no longer contradict executions.** A check composed against one context
  but rejected on another carried both an execution ledger row and persisted per-context
  exclusions; per-context rejections now persist only when no context admitted the check.
- **`artemis regression run` works against custom-port targets again.** The replay's derived
  scope permitted only http/https while the DNS-pinning gate classifies every non-default port
  as a Tcp candidate, and its only allowlist entry was a URL prefix - which compiles to no
  hostname or IP-range matcher at all - so every replay failed closed with "not covered by any
  allowlist entry". The replay scope now allowlists the host itself (CIDR form for address
  literals) beside the path-scoped URL prefix and permits Tcp like every assessment scope does;
  replays execute through the same pinned-DNS safe engine as assessments.
- **`artemis audit export` archives are byte-clean machine artifacts.** The human summary line
  ("exported N audit event(s)...") was prepended to the archived text in default mode, so files
  written via `--output`, plain stdout redirects, and pipes all failed an external auditor's
  `json.load` / CSV reader before parsing started. Every write path now carries exactly the
  hashed payload; the summary stays console-only.
- **Every planning decision is now a stored fact, including the launcher's.** Composition in
  `AssessmentLauncher` decided which check families were ever constructed (web/API battery for
  URL origins, network-free repository analyses otherwise) without recording anything, so
  coverage could only report those checks as "no execution, no stored reason" on brand-new
  databases - mislabeled as pre-ledger assessments. The launcher now hands every omission to the
  engine as an explicit composition exclusion (`NO_HTTP_ORIGIN`, `TARGET_TYPE_MISMATCH`,
  `OPENAPI_DOCUMENT_ABSENT`), persisted with the plan's own exclusions before any work runs.
  A production-path launch leaves the unexplained column of `artemis coverage show` empty by
  construction; only genuinely pre-ledger assessments still show gaps, and the surface now says
  exactly that.

### Changed

- `AssessmentRunRequest` gains optional `CompositionExclusions`; hosts that compose checks
  themselves can record their decisions through the same ledger. Repository scopes launched with
  an explicit `--base-url` now also run their source and dependency analyses instead of nothing.

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
