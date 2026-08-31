#!/usr/bin/env bash
#
# Artemis Assessment Workflow Lifecycle - End-to-End Demonstration
#
# Demonstrates Artemis complete defensive-security assessment workflow as a real,
# repeatable end-to-end simulation using ONLY audit/assessment capabilities
# (it never modifies the scanned target):
#
#   1. SCOPE     - author and validate the authorization boundary
#   2. ASSESS    - run the assessment (checks execute within budget)
#   3. FINDINGS  - list the deduplicated findings
#   4. TRIAGE    - record an operator decision on a finding
#   5. BASELINE  - snapshot the assessment into a security baseline
#   6. COMPARE   - compare a re-assessment against the baseline (drift gate)
#   7. REPORT    - generate an audited report
#
# Usage: ./e2e/workflow_lifecycle_demo.sh [TARGET_PATH]
#   TARGET_PATH defaults to a small bundled fixture so the demo is self-contained.

set -euo pipefail

ARTIMIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="dotnet run --project ${ARTIMIS_DIR}/src/ACT.Cli --no-build --"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

step() { printf "\n\033[1;34m==> %s\033[0m\n" "$1"; }

# 0. Pick a target: self-contained fixture by default, or a real repo via $1.
TARGET="${1:-}"
if [[ -z "${TARGET}" ]]; then
  TARGET="${WORKDIR}/fixture"
  mkdir -p "${TARGET}/src"
  cat > "${TARGET}/src/app.py" <<'PY'
import requests
API_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
session = requests.Session()
session.verify = False
PY
  echo "Using self-contained fixture at ${TARGET}"
else
  echo "Using target: ${TARGET}"
fi

# 1. SCOPE
step "1/7 SCOPE: author and validate the assessment scope"
SCOPE_ID="$(uuidgen)"
ASSESSMENT_ID="$(uuidgen)"
SCOPE_FILE="${WORKDIR}/scope.json"
cat > "${SCOPE_FILE}" <<JSON
{
  "scopeId": "${SCOPE_ID}",
  "assessmentId": "${ASSESSMENT_ID}",
  "operatorIdentity": "demo-operator",
  "organization": "Artemis Demo",
  "targetType": "LocalSourceRepository",
  "allowlistedTargets": ["${TARGET}"],
  "excludedTargets": [],
  "permittedProtocols": [],
  "permittedPorts": [],
  "requestsPerSecond": 5,
  "concurrencyLimit": 2,
  "maxRuntimeSeconds": 600,
  "maxRequests": 500,
  "allowedCategories": ["Source", "Dependency", "Configuration"],
  "prohibitedCategories": [],
  "emergencyStopEnabled": true,
  "evidenceRetentionDays": 30,
  "redactionPolicy": "Standard",
  "authorizationStatement": "I confirm I own and am authorized to assess this local source repository."
}
JSON
${CLI} scope validate --file "${SCOPE_FILE}"

# 2. ASSESS
step "2/7 ASSESS: run the assessment within the validated scope"
${CLI} assessment start --scope "${SCOPE_FILE}"

# 3. FINDINGS
step "3/7 FINDINGS: list findings for the assessment"
${CLI} finding list --assessment "${ASSESSMENT_ID}"

# 4. TRIAGE
step "4/7 TRIAGE: record an operator decision on the highest-priority finding"
TOP_FINDING="$( ${CLI} finding list --assessment "${ASSESSMENT_ID}" --json 2>/dev/null \\  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(max(d,key=lambda f:f["priorityScore"])["FindingId"]) if d else ""' )"
if [[ -n "${TOP_FINDING}" ]]; then
  ${CLI} finding triage "${TOP_FINDING}" --status Confirmed \\    --note "Confirmed via workflow demo" --actor "demo-operator"
else
  echo "(no findings to triage)"
fi

# 5. BASELINE
step "5/7 BASELINE: snapshot the assessment into a security baseline"
${CLI} baseline create --assessment "${ASSESSMENT_ID}" --name "demo-baseline" --actor "demo-operator"

# 6. COMPARE
step "6/7 COMPARE: re-assess and compare against the baseline (drift gate)"
REASSESS_ID="$(uuidgen)"
SCOPE_FILE2="${WORKDIR}/scope2.json"
sed "s/${ASSESSMENT_ID}/${REASSESS_ID}/" "${SCOPE_FILE}" > "${SCOPE_FILE2}"
${CLI} assessment start --scope "${SCOPE_FILE2}"
if ${CLI} baseline compare --assessment "${REASSESS_ID}"; then
  echo "Drift gate: PASS (no drift)"
else
  echo "Drift gate: drift detected (expected on a re-run)"
fi

# 7. REPORT
step "7/7 REPORT: generate an audited Markdown report"
REPORT_OUT="${WORKDIR}/report"
mkdir -p "${REPORT_OUT}"
${CLI} report generate --assessment "${ASSESSMENT_ID}" --format markdown --out "${REPORT_OUT}" --actor "demo-operator"
echo "Report written to: ${REPORT_OUT}"
ls -la "${REPORT_OUT}"

printf '\n\033[1;32mWorkflow lifecycle complete.\033[0m\n'
