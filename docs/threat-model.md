# Artemis Threat Model

Artemis is a defensive assessment engine. The model below enumerates what it defends against,
what it refuses to do, and the trust boundaries it enforces. It follows a STRIDE-flavored
structure applied to the tool itself, because a security scanner that can be turned by its
target is worse than no scanner.

## Assets to protect

1. **Authorization integrity** — the invariant that only allowlisted targets are ever contacted.
2. **Evidence integrity** — stored evidence and audit trail reflect what actually happened.
3. **Operator secrets** — credentials supplied as test fixtures never persist beyond memory.
4. **The operator's machine** — hostile target responses must not execute inside the scanner.
5. **Assessment honesty** — reports must never overstate coverage or currency of feed data.

## Trust boundaries

| Boundary | Threat | Enforcement |
|---|---|---|
| Scope file -> engine | Malicious/ambiguous configuration widens targets | Structural validation + compilation fails closed on ambiguity; single-label hosts rejected outside test environments |
| DNS -> connections | Rebinding / alias games bypass name-based allowlists | One pinned resolution per host per run; private-target scopes require every resolved address inside configured CIDRs; connections use pinned addresses only |
| HTTP redirects -> engine | Redirect chain walks out of scope or downgrades TLS | Every hop re-evaluated by the scope validator; HTTPS->HTTP blocked; hop count capped |
| Target responses -> scanner | Decompression bombs, endless streams, header injection into logs | Hard caps on transfer AND decompressed bytes; bounded reads with timeouts; headers carried as data |
| Scanned content -> LLM | Prompt injection via page/API/source text instructing the tool | All target content wrapped in UNTRUSTED delimiters; providers are advisory-only by type system; outputs scanned for directive patterns and never actionable |
| Repository -> analyzer | Symlink escape reads outside root; ReDoS rules | Final symlink resolution must stay under root else skipped and recorded; regexes carry match timeouts; size/depth/file-count caps |
| Local storage -> attacker-with-file-access | Evidence contains secrets; audit log tampering | Redaction before persistence (standard/strict); hash-chained audit entries verifiable end-to-end; WAL checkpointed on secure delete |
| Schedules -> policy drift | Cron jobs silently widening behavior | Schedules reference persisted scopes only; they cannot alter scope or policy |

## Explicit refusals (by design)

No credential theft, keylogging, cookie theft, token harvesting, phishing generation, malware
or ransomware construction, persistence mechanisms, privilege-escalation payloads, destructive
exploitation, RCE payload weaponization, evasion/AV-bypass, process injection, shellcode
generation, mass internet scanning, denial-of-service testing, destructive fuzzing, or data
exfiltration. Vulnerability validation prefers passive observation, safe protocol checks,
harmless requests, local proof-of-concept simulation, and operator-provided test fixtures.

## Failure posture

Every subsystem maps errors to a category (Configuration, Scope, Network, Authorization,
Parser, SecurityCheck, Persistence, Report, ExternalFeed, Llm, Internal). Ambiguity anywhere
in authorization resolves to DENY. Feed staleness is surfaced, never hidden. Reports must
distinguish tested / not tested / inaccessible / inconclusive / confirmed / inferred.

## Residual risks (honest disclosure)

- Authenticode signing requires a Windows build host with an organization certificate; the pipeline verifies signatures when configured but cannot conjure trust from a dev machine.
- TLS legacy-version probing depends on OS TLS stacks; unsupported probes degrade to "untestable here" rather than false findings.
- SQLite evidence at rest is protected by redaction and retention sweeps, not full-database encryption; full crypto-shredding is documented as out of scope.
