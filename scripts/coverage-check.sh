#!/bin/bash
set -e

# Fixed locale so the percentages print with a decimal point regardless of the
# developer's LC_NUMERIC.
export LC_ALL=C

# Minimum statement coverage per package, weighted by risk. This list is the
# machine-readable copy of the thresholds table in README.md; update both
# together. Packages that are not listed are reported but never fail the check.
THRESHOLDS="
internal/services=85
internal/api/middleware=85
internal/api=80
internal/api/handlers=80
pkg/env=80
pkg/ratelimit=80
internal/repositories=70
internal/logging=70
internal/mail=50
total=70
"

# COVERAGE_PKGS is exported by the Makefile so the package list, including the
# exclusions, is defined in one place. Recompute it when run directly.
PKGS="${COVERAGE_PKGS:-$(go list ./... | grep -Ev "/(cmd/|internal/db$|utils$)")}"

PROFILE=$(mktemp)
trap 'rm -f "$PROFILE"' EXIT

echo "Checking coverage thresholds..."
# shellcheck disable=SC2086
go test -coverprofile="$PROFILE" $PKGS > /dev/null

REPORT=$(awk -v thresholds="$THRESHOLDS" '
BEGIN {
    split(thresholds, lines, "\n")
    for (i in lines) {
        if (split(lines[i], kv, "=") == 2) min[kv[1]] = kv[2]
    }
}
NR > 1 {
    pkg = $1
    sub(/\/[^\/]*:.*/, "", pkg)
    sub(/.*auth-service\//, "", pkg)

    statements[pkg] += $2
    total += $2
    if ($3 > 0) {
        covered[pkg] += $2
        totalCovered += $2
    }
}
END {
    for (pkg in statements) {
        report(pkg, covered[pkg], statements[pkg])
    }
    report("total", totalCovered, total)
}

function report(name, cov, stmts,    pct, floor, status) {
    if (stmts == 0) return

    pct = 100 * cov / stmts
    floor = (name in min) ? min[name] : 0
    status = (pct + 0.05 < floor) ? "FAIL" : "ok"

    printf "%s|%.1f|%d|%s\n", name, pct, floor, status
}
' "$PROFILE")

# Packages alphabetically, the aggregate last.
{
    echo "$REPORT" | grep -v '^total|' | sort
    echo "$REPORT" | grep '^total|'
} | awk -F'|' '{
    if ($4 == "FAIL")
        printf "  %-28s %5.1f%%  (min %d%%)  FAIL\n", $1, $2, $3
    else if ($3 == 0)
        printf "  %-28s %5.1f%%  (no minimum)\n", $1, $2
    else
        printf "  %-28s %5.1f%%  (min %d%%)  ok\n", $1, $2, $3
}'

if echo "$REPORT" | grep -q '|FAIL$'; then
    echo "✗ Coverage below the documented minimum"
    exit 1
fi

echo "✓ All packages meet their coverage minimum"
