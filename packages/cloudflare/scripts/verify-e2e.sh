#!/bin/bash
# E2E verification script for verifiable-delete Cloudflare adapter.
# Usage: ./scripts/verify-e2e.sh [base_url]
# Default: http://localhost:8787

set -euo pipefail

BASE_URL="${1:-http://localhost:8787}"
PASS=0
FAIL=0

check() {
  local desc="$1"
  local result="$2"
  if [ "$result" = "true" ]; then
    echo "  ✓ $desc"
    PASS=$((PASS + 1))
  else
    echo "  ✗ $desc"
    FAIL=$((FAIL + 1))
  fi
}

echo "=== Verifiable Delete E2E Verification ==="
echo "Base URL: $BASE_URL"
echo ""

# 1. GET / — Demo UI
echo "--- UI ---"
UI=$(curl -s "$BASE_URL/")
check "GET / returns DOCTYPE" "$(echo "$UI" | head -1 | grep -q DOCTYPE && echo true || echo false)"
check "GET / contains Verifiable Delete" "$(echo "$UI" | grep -q 'Verifiable Delete' && echo true || echo false)"

# 2. POST /demo/delete — SSE stream
echo ""
echo "--- Demo Pipeline ---"
SSE=$(curl -s -X POST "$BASE_URL/demo/delete?nodelay=1" \
  -H "Content-Type: application/json" \
  -d '{"data":"E2E test data"}')
check "SSE contains step events" "$(echo "$SSE" | grep -q 'event: step' && echo true || echo false)"
check "SSE contains done event" "$(echo "$SSE" | grep -q 'event: done' && echo true || echo false)"
STEP_COUNT=$(echo "$SSE" | grep -c 'event: step' || true)
check "SSE has 18 step events (9 running + 9 complete)" "$([ "$STEP_COUNT" = "18" ] && echo true || echo false)"
INSPECTOR_COUNT=$(echo "$SSE" | grep -c 'event: inspector' || true)
check "SSE has 9 inspector events" "$([ "$INSPECTOR_COUNT" = "9" ] && echo true || echo false)"
check "SSE contains smt_proven phase" "$(echo "$SSE" | grep -q 'smt_proven' && echo true || echo false)"

# 3. GET /log — Tree head
echo ""
echo "--- Transparency Log ---"
LOG=$(curl -s "$BASE_URL/log")
check "GET /log returns treeSize" "$(echo "$LOG" | grep -q 'treeSize' && echo true || echo false)"
check "GET /log returns rootHash" "$(echo "$LOG" | grep -q 'rootHash' && echo true || echo false)"
check "GET /log returns signature" "$(echo "$LOG" | grep -q 'signature' && echo true || echo false)"

# 4. GET /log/entries — Entries
ENTRIES=$(curl -s "$BASE_URL/log/entries")
check "GET /log/entries returns array" "$(echo "$ENTRIES" | grep -q '^\[' && echo true || echo false)"

# 5. Run demo 2 more times and check consistency
echo ""
echo "--- Multi-run consistency ---"
curl -s -X POST "$BASE_URL/demo/delete?nodelay=1" -H "Content-Type: application/json" -d '{"data":"test2"}' > /dev/null
curl -s -X POST "$BASE_URL/demo/delete?nodelay=1" -H "Content-Type: application/json" -d '{"data":"test3"}' > /dev/null
LOG2=$(curl -s "$BASE_URL/log")
TREE_SIZE=$(echo "$LOG2" | python3 -c "import sys,json; print(json.load(sys.stdin).get('treeSize',0))" 2>/dev/null || echo "0")
check "Tree size >= 3 after 3 demos" "$([ "$TREE_SIZE" -ge 3 ] 2>/dev/null && echo true || echo false)"

# 6. GET /log/consistency
if [ "$TREE_SIZE" -ge 3 ]; then
  CONSISTENCY=$(curl -s "$BASE_URL/log/consistency?from=1&to=$TREE_SIZE")
  check "Consistency proof has hashes" "$(echo "$CONSISTENCY" | grep -q 'hashes' && echo true || echo false)"
fi

# 7. Unknown route
echo ""
echo "--- Error handling ---"
NOT_FOUND=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/nonexistent")
check "GET /nonexistent returns 404" "$([ "$NOT_FOUND" = "404" ] && echo true || echo false)"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" = "0" ] && echo "All checks passed!" || echo "Some checks failed."
exit "$FAIL"
