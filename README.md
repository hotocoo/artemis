# Artemis

**Artemis** is an autonomous, local-first **defensive** security assessment platform for systems you are explicitly authorized to test. It discovers authorized assets, validates scope deterministically, runs non-destructive security checks, collects tamper-evident evidence, deduplicates findings, scores risk honestly, supports audited operator triage of findings, stores audited security baselines that turn later runs into honest drift reports, generates regression tests from operator-supplied fixtures, and produces machine- and human-readable reports (JSON / CSV / Markdown / HTML / SARIF).

> Internal module prefix `ACT.*` (Artemis Core Toolkit) names the assemblies and namespaces; the product name is **Artemis**.

## Non-negotiable safety model

- Every assessment requires an explicit **Scope Configuration**: allowlist, exclusions, permitted protocols/ports, rate limit, concurrency, max runtime, max requests, category policy, emergency stop, retention and redaction policy, and a signed authorization statement.
- **DNS resolution is never authorization. Redirects are re-authorized hop-by-hop. HTTPS-to-HTTP downgrades are blocked. Resolved addresses must stay inside private-target scopes.**
- No credential theft, no malware, no destructive testing, no mass internet scanning. Checks are passive or safe-request-only unless explicitly configured otherwise.
- The engine **fails closed** on ambiguous scope, malformed config, out-of-scope redirects, oversized responses, and policy violations.

## Quick start (development)

`bash`
dotnet build Artemis.slnx
dotnet test tests/ACT.Tests/ACT.Tests.csproj

# validate a scope file before anything touches a network
artemis scope validate --file samples/scope.example.json
`

## Repository layout

| Path | Purpose |
|------|---------|
| src/ACT.Contracts | Frozen typed contracts (scope, findings, evidence, checks, config) |
| src/ACT.Scope | IPv4/IPv6 CIDR math, target matchers, fail-closed validator, DNS pinning gate |
| src/ACT.Network | Safe HTTP engine (redirect re-auth, decompression-bomb defense), token bucket, TCP/TLS probes |
| src/ACT.Core | Assessment pipeline, orchestrator, dedup, regression engine, cron scheduler |
| src/ACT.Policy | Deterministic policy evaluation + emergency stop |
| src/ACT.Risk | Deterministic scoring/prioritization, honest CVSS-style estimation |
| src/ACT.Evidence | Secret redaction before persistence |
| src/ACT.Tls | TLS protocol/certificate/cipher checks |
| src/ACT.Web | HTTP header/cookie/CORS/cache checks |
| src/ACT.Api | OpenAPI-driven API surface analysis (safe behavioral checks) |
| src/ACT.SourceAnalysis | Local repository static analysis with symlink-safe traversal |
| src/ACT.DependencyAnalysis | Manifest parsing, SBOM (CycloneDX), advisory feeds (OSV/offline) |
| src/ACT.Persistence | SQLite storage, migrations, hash-chained audit log |
| src/ACT.Reporting | Report formatters incl. SARIF 2.1, CI gate, baseline drift |
| src/ACT.Llm | Optional LLM providers; untrusted-data fencing; fully functional offline without them |
| src/ACT.Cli | artemis command-line interface |
| src/ACT.Desktop | Operator console host (loopback web UI over the same engine) |
| lab/ACT.Lab | Disposable intentionally-vulnerable fixtures for verifying the scanner - LOOPBACK ONLY |
| tests/ | Unit, integration, end-to-end, and adversarial safety tests |

## Documentation

- docs/threat-model.md - what we defend against, including hostile targets and prompt injection
- docs/architecture.md - module map and data flow
- docs/operator-manual.md - running assessments safely
- docs/developer-manual.md - building, testing, contributing checks

## Status

Production build targeting Windows x64 self-contained single-file publish; cross-platform development supported.
