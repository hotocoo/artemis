# Artemis Developer Manual

## Environment

- .NET SDK 10.x (see global.json), any OS for development; Windows required only for Authenticode signing.
- Build: `dotnet build Artemis.slnx` - warnings are errors, analyzers on, nullable enabled.
- Test tiers: unit (ACT.Tests), integration/E2E against the disposable lab (ACT.IntegrationTests), adversarial safety (ACT.SecurityTests), benchmarks (ACT.Benchmarks), and a Playwright-driven e2e chaos workflow (`e2e/`) that drives the real built binaries through a hostile operator lifecycle (emergency stops mid-flight, crashes, concurrency, triage, reports, audit integrity, persistence) - run locally with `bash e2e/run.sh`.

## Writing a security check

1. Implement `ISecurityCheck`. Metadata is validated fail-closed at composition: honest SafetyLevel, request footprint, permissions, supported target kinds, evidence types.
2. Take everything through `SecurityCheckContext`; return everything through typed results. No statics, no ambient state.
3. All network I/O goes through `context.Assessment.Http` (the safe engine) after `context.Assessment.ScopeValidator` verdicts. There is no other outbound path by design.
4. Create findings via `FindingFactory.Create`; fingerprints derive from check+target+resource+class ONLY (never timestamps/evidence text) so deduplication is stable across runs.
5. Evidence via `context.Assessment.Evidence` - it redacts at construction; raw secrets must not exist in memory beyond the immediate request scope anyway.
6. Register the check in the composition root's registry with a deterministic id like `ACT-<AREA>-<NAME>-<NNN>`.

### Rules of engagement inside checks

- GET/HEAD/OPTIONS by default; mutations only through explicit operator fixtures.
- Skip honestly (`Skipped_NotApplicable`/Skipped_OutOfScope) instead of guessing.
- Catch `ActException` to convert failures into Failed_FailedClosed results; unexpected exceptions are contained by the engine and audited.

## Persistence & schema

Migrations live in ACT.Persistence as ordered, checksummed SQL steps. All access is parameterized; timestamps ISO-8601 UTC; findings dedupe on (assessment, fingerprint); terminal finding statuses are never resurrected by reobservation.

## Release flow

compile -> tests (all tiers) -> forbidden-marker scan -> publish win-x64 single-file -> checksums + manifest -> optional Authenticode sign (SHA-256 + RFC 3161) -> verify signatures. See .github/workflows/release.yml and scripts/.

## Prohibited contributions

No TODO/FIXME/HACK markers, no mocks in product code, no hardcoded endpoints/credentials/sample data, no new dependencies without justification, no capability listed under 'Explicit refusals' in the threat model.