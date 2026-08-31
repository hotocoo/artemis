# Artemis Assessment Report — LocalSourceRepository

## Executive Summary

- Assessment **LocalSourceRepository** (state: Completed), operator acotech (security team), organization Local Dev Security.
- Report generated 2026-08-31T05:24:21.9882550Z using 0.1.5.
- Findings: 8 total — critical 1, high 4, medium 3, low 0, informational 0.

## Risk Summary

| Severity | Findings |
| --- | ---: |
| Critical | 1 |
| High | 4 |
| Medium | 3 |

- Highest observed severity: Critical.
- Average priority score: 48.38.

## Technical Findings

### Critical

#### Vulnerable dependency vite@5.4.21

- Id: `14016e70-2988-4e7a-b471-c6ef1c679897`
- Check: `ACT-DEP-AUDIT-001` · Category: Dependency · Confidence: High · Status: New
- Target: `vite@5.4.21`
- First seen: 2026-08-31T05:19:26.4781750Z · Last seen: 2026-08-31T05:19:26.4781750Z
- Priority score: 80 · Fingerprint: `5a0bd7f907bcf6361d963f93218aa102ae0ee5891a074c6c89ce693a6dbdb6eb` · Exploitability indicator present

Advisory GHSA-TEST-VITE-001 affects this package in range <5.5.0. Fixed in 5.5.0.

**Why it matters:** Known-vulnerable package versions carry publicly documented attack techniques that automated attackers apply without modification.

**Remediation:** Update vite to remove exposure to GHSA-TEST-VITE-001.
1. Upgrade vite to 5.5.0 or later.
2. Re-run the assessment to confirm the fixed version resolved the advisory.

### High

#### Vulnerable dependency vue@3.5.35

- Id: `1be5664e-8cac-4010-9b63-f456897f902d`
- Check: `ACT-DEP-AUDIT-001` · Category: Dependency · Confidence: High · Status: New
- Target: `vue@3.5.35`
- First seen: 2026-08-31T05:19:26.4881010Z · Last seen: 2026-08-31T05:19:26.4881010Z
- Priority score: 70 · Fingerprint: `b088e52ebb8844fbba3359c19295d0a1a135b3674aa5a58519ae3054a7f4d373` · Exploitability indicator present

Advisory GHSA-TEST-VUE-001 affects this package in range <3.6.0. Fixed in 3.6.0.

**Why it matters:** Known-vulnerable package versions carry publicly documented attack techniques that automated attackers apply without modification.

**Remediation:** Update vue to remove exposure to GHSA-TEST-VUE-001.
1. Upgrade vue to 3.6.0 or later.
2. Re-run the assessment to confirm the fixed version resolved the advisory.

#### Potential Hardcoded Credential

- Id: `5f73712c-c5af-4076-bfb2-227e2bcd40f0`
- Check: `ACT-WEB-CONFIG-001` · Category: Configuration · Confidence: Medium · Status: New
- Target: `.env.example`
- First seen: 2026-08-31T05:19:26.5189290Z · Last seen: 2026-08-31T05:19:26.5189550Z
- Priority score: 47 · Fingerprint: `66422602c47e0d6f8424ef3979cc0db2e38c955f9f8ceace1025307cf8159b06`

Line 29 contains what appears to be a hardcoded credential.

**Why it matters:** Insecure configurations can lead to security vulnerabilities.

**Remediation:** Review and secure the configuration.
1. Review the configuration file for security best practices.
2. Apply recommended security settings.

#### Potential Hardcoded Credential

- Id: `c9c28fca-82bc-467a-8a6e-96e35f4978de`
- Check: `ACT-WEB-CONFIG-001` · Category: Configuration · Confidence: Medium · Status: New
- Target: `test.env`
- First seen: 2026-08-31T05:19:26.5190070Z · Last seen: 2026-08-31T05:19:26.5190150Z
- Priority score: 47 · Fingerprint: `89828ea7c6ca9384f96ab8a528611f33154f6f3052e29922039a34eb37ff33e8`

Line 18 contains what appears to be a hardcoded credential.

**Why it matters:** Insecure configurations can lead to security vulnerabilities.

**Remediation:** Review and secure the configuration.
1. Review the configuration file for security best practices.
2. Apply recommended security settings.

#### Potential Hardcoded Credential

- Id: `86010fa5-786c-4fe0-89d1-1a6057f5bbb6`
- Check: `ACT-WEB-CONFIG-001` · Category: Configuration · Confidence: Medium · Status: New
- Target: `dev.env`
- First seen: 2026-08-31T05:19:26.5190660Z · Last seen: 2026-08-31T05:19:26.5190810Z
- Priority score: 47 · Fingerprint: `ca06444050541ef45c6f3c4ea5c1f86182846df9d72884b235f129d65eaa0b48`

Line 22 contains what appears to be a hardcoded credential.

**Why it matters:** Insecure configurations can lead to security vulnerabilities.

**Remediation:** Review and secure the configuration.
1. Review the configuration file for security best practices.
2. Apply recommended security settings.

### Medium

#### Generic credential assignment with high-variety value

- Id: `0407acf3-eff9-4900-b34a-548e7ad74bb7`
- Check: `ACT-SRC-SCAN-001` · Category: Source · Confidence: Medium · Status: New
- Target: `frontend/src/stores/messages.ts`
- First seen: 2026-08-31T05:19:26.5444760Z · Last seen: 2026-08-31T05:19:26.5444760Z
- Priority score: 32 · Fingerprint: `19992f71e97ed01d92c93a048b8555ab5c68aedbe9d7f076c3b63c79d5929893`

1 location(s) matched rule SRC-SECRET-002 in this file. Every matched location is attached as evidence with a trimmed line snippet.

**Why it matters:** Long mixed-class values assigned to password-like names are probable live secrets.

**Remediation:** Replace with configuration or a secret store; verify the value was never deployed.

#### Generic credential assignment with high-variety value

- Id: `eda3f341-b91a-4a52-a683-bb0e700d4633`
- Check: `ACT-SRC-SCAN-001` · Category: Source · Confidence: Medium · Status: New
- Target: `scripts/phase2_test.sh`
- First seen: 2026-08-31T05:19:26.4744960Z · Last seen: 2026-08-31T05:19:26.4744960Z
- Priority score: 32 · Fingerprint: `6cd6fe9544e3bbe9243f2d491c4b154da0536082983fb8c90b17643f8e9420a5`

1 location(s) matched rule SRC-SECRET-002 in this file. Every matched location is attached as evidence with a trimmed line snippet.

**Why it matters:** Long mixed-class values assigned to password-like names are probable live secrets.

**Remediation:** Replace with configuration or a secret store; verify the value was never deployed.

#### Generic credential assignment with high-variety value

- Id: `9cdd9e56-360f-4596-98e6-65a02883ea2d`
- Check: `ACT-SRC-SCAN-001` · Category: Source · Confidence: Medium · Status: New
- Target: `backend/internal/agent/agent_scope_invariant_test.go`
- First seen: 2026-08-31T05:19:26.4988180Z · Last seen: 2026-08-31T05:19:26.4988180Z
- Priority score: 32 · Fingerprint: `82b4f8baca52d621f1e10ad45555873d005be3973a2cf23d5583955a2f1d123e`

2 location(s) matched rule SRC-SECRET-002 in this file. Every matched location is attached as evidence with a trimmed line snippet.

**Why it matters:** Long mixed-class values assigned to password-like names are probable live secrets.

**Remediation:** Replace with configuration or a secret store; verify the value was never deployed.

## Remediation Plan

1. **Vulnerable dependency vite@5.4.21** — priority 80; check `ACT-DEP-AUDIT-001` on `vite@5.4.21`; start with: Upgrade vite to 5.5.0 or later.
2. **Vulnerable dependency vue@3.5.35** — priority 70; check `ACT-DEP-AUDIT-001` on `vue@3.5.35`; start with: Upgrade vue to 3.6.0 or later.
3. **Potential Hardcoded Credential** — priority 47; check `ACT-WEB-CONFIG-001` on `.env.example`; start with: Review the configuration file for security best practices.
4. **Potential Hardcoded Credential** — priority 47; check `ACT-WEB-CONFIG-001` on `test.env`; start with: Review the configuration file for security best practices.
5. **Potential Hardcoded Credential** — priority 47; check `ACT-WEB-CONFIG-001` on `dev.env`; start with: Review the configuration file for security best practices.
6. **Generic credential assignment with high-variety value** — priority 32; check `ACT-SRC-SCAN-001` on `frontend/src/stores/messages.ts`; start with: Replace with configuration or a secret store; verify the value was never deployed.
7. **Generic credential assignment with high-variety value** — priority 32; check `ACT-SRC-SCAN-001` on `scripts/phase2_test.sh`; start with: Replace with configuration or a secret store; verify the value was never deployed.
8. **Generic credential assignment with high-variety value** — priority 32; check `ACT-SRC-SCAN-001` on `backend/internal/agent/agent_scope_invariant_test.go`; start with: Replace with configuration or a secret store; verify the value was never deployed.

## Regression Coverage

- 0 of 8 findings carry a regression test identifier.

## Assessment Scope

- Target type: LocalSourceRepository
- Allowlisted targets: /Users/acotech/workspace/chatroom
- Excluded targets: (none)
- Permitted protocols: (none)
- Permitted ports: (none)
- Rate limit: 5 req/s · Concurrency limit: 2 · Max requests: 2000 · Max runtime: 01:00:00
- Redaction policy: Standard
- Allowed categories: Source, Dependency, Configuration
- Prohibited categories: (none)
- Authorization statement: "I confirm I own and am authorized to assess this local source repository."

## Coverage & Limitations

- Coverage counts: tested 6, not tested 0, inaccessible 0, inconclusive 0, confirmed 0, inferred 6.
- Limitations: Scope-limited assessment; absence of findings does not imply absence of vulnerabilities.


_Generated 2026-08-31T05:24:21.9882550Z by 0.1.5._
