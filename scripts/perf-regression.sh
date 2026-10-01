#!/usr/bin/env bash
# Performance regression tracking for Artemis benchmarks.
# Stores baseline results and compares new runs against them.
#
# Usage:
#   scripts/perf-regression.sh baseline   # Run benchmarks and store as baseline
#   scripts/perf-regression.sh compare    # Run benchmarks and compare to baseline
#   scripts/perf-regression.sh report     # Show baseline and latest results

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE_FILE="$REPO_ROOT/tests/ACT.Benchmarks/baseline.json"
LATEST_FILE="$REPO_ROOT/tests/ACT.Benchmarks/latest.json"
THRESHOLD="${PERF_REGRESSION_THRESHOLD:-1.20}"  # 20% default threshold

run_benchmarks() {
    local output_file="$1"
    echo "Building benchmarks..."
    cd "$REPO_ROOT"
    dotnet build tests/ACT.Benchmarks/ACT.Benchmarks.csproj -c Release --no-restore 2>&1 | tail -3

    echo "Running benchmarks..."
    local bench_dll="$REPO_ROOT/tests/ACT.Benchmarks/bin/Release/net10.0/ACT.Benchmarks.dll"
    echo "*" | dotnet "$bench_dll" \
        -e csv \
        -a "$REPO_ROOT/BenchmarkDotNet.Artifacts" 2>&1 | tail -10

    # Parse the CSV report into JSON
    local csv_file
    csv_file=$(ls -t "$REPO_ROOT/BenchmarkDotNet.Artifacts/results/"*report.csv 2>/dev/null | head -1)
    if [[ -z "$csv_file" ]]; then
        echo "ERROR: Could not find benchmark CSV report"
        return 1
    fi

    # Convert CSV to JSON using awk (columns: 1=Method, 45=Mean, 46=Error, 47=StdDev)
    awk -F',' 'NR > 1 && $1 != "" {
        gsub(/"/, "", $1); gsub(/ /, "", $45); gsub(/ /, "", $46); gsub(/ /, "", $47)
        printf "{\"benchmark\":\"%s\",\"mean\":\"%s\",\"error\":\"%s\",\"stddev\":\"%s\"}\n", $1, $45, $46, $47
    }' "$csv_file" > "$output_file.tmp"

    # Wrap in JSON array
    echo "[" > "$output_file"
    local count=$(wc -l < "$output_file.tmp" | tr -d ' ')
    if [[ "$count" -gt 0 ]]; then
        # macOS doesn't support head -n -1, use awk instead
        awk 'NR>1{print prev","} {prev=$0} END{print prev}' "$output_file.tmp" >> "$output_file"
    fi
    echo "]" >> "$output_file"
    rm "$output_file.tmp"

    echo "Results saved to $output_file"
}

store_baseline() {
    run_benchmarks "$LATEST_FILE"
    cp "$LATEST_FILE" "$BASELINE_FILE"
    echo "Baseline stored."
}

compare_to_baseline() {
    if [[ ! -f "$BASELINE_FILE" ]]; then
        echo "ERROR: No baseline found. Run 'scripts/perf-regression.sh baseline' first."
        return 1
    fi

    run_benchmarks "$LATEST_FILE"

    echo ""
    echo "Comparing against baseline (threshold: ${THRESHOLD}x)..."
    echo "=================================================="

    # Compare each benchmark
    local regressions=0
    local improvements=0
    local unchanged=0

    while IFS= read -r line; do
        local benchmark mean
        benchmark=$(echo "$line" | grep -oP '"benchmark":"[^"]+"' | cut -d'"' -f4)
        mean=$(echo "$line" | grep -oP '"mean":"[^"]+"' | cut -d'"' -f4)

        if [[ -z "$benchmark" || -z "$mean" ]]; then
            continue
        fi

        # Find baseline value
        local baseline_mean
        baseline_mean=$(grep "\"benchmark\":\"$benchmark\"" "$BASELINE_FILE" | grep -oP '"mean":"[^"]+"' | cut -d'"' -f4)

        if [[ -z "$baseline_mean" ]]; then
            echo "  $benchmark: NEW (no baseline)"
            continue
        fi

        # Compare means (simple numeric comparison)
        local ratio
        ratio=$(awk "BEGIN {printf \"%.2f\", $mean / $baseline_mean}")

        if (( $(awk "BEGIN {print ($ratio > $THRESHOLD) ? 1 : 0}") )); then
            echo "  ⚠️  REGRESSION: $benchmark: ${baseline_mean} → ${mean} (${ratio}x)"
            ((regressions++))
        elif (( $(awk "BEGIN {print ($ratio < 1.0/$THRESHOLD) ? 1 : 0}") )); then
            echo "  ✅ IMPROVEMENT: $benchmark: ${baseline_mean} → ${mean} (${ratio}x)"
            ((improvements++))
        else
            echo "  ✓ UNCHANGED: $benchmark: ${baseline_mean} → ${mean} (${ratio}x)"
            ((unchanged++))
        fi
    done < "$LATEST_FILE"

    echo ""
    echo "Summary: $regressions regressions, $improvements improvements, $unchanged unchanged"

    if [[ $regressions -gt 0 ]]; then
        echo ""
        echo "PERFORMANCE REGRESSION DETECTED!"
        return 1
    fi

    return 0
}

show_report() {
    echo "Baseline:"
    if [[ -f "$BASELINE_FILE" ]]; then
        cat "$BASELINE_FILE"
    else
        echo "  (none)"
    fi

    echo ""
    echo "Latest:"
    if [[ -f "$LATEST_FILE" ]]; then
        cat "$LATEST_FILE"
    else
        echo "  (none)"
    fi
}

case "${1:-compare}" in
    baseline) store_baseline ;;
    compare) compare_to_baseline ;;
    report) show_report ;;
    *) echo "Usage: $0 {baseline|compare|report}"; exit 1 ;;
esac
