#!/usr/bin/env bash
# Round-trip clean → smudge for IP, password, CIDR, and JSON password (findings 1–4, 7).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILTER="${ROOT}/scripts/sanitize_filter.py"
FIXTURES="${ROOT}/tests/fixtures"
CONFIG="${FIXTURES}/sanitization.json"
LEARNED="${FIXTURES}/.sanitization.learned.test.json"

export SANITIZATION_CONFIG="${CONFIG}"
export SANITIZATION_LEARNED="${LEARNED}"

rm -f "${LEARNED}"

fail() {
  echo "roundtrip test FAILED: $*" >&2
  exit 1
}

roundtrip_file() {
  local file="$1"
  local original cleaned restored
  original="$(cat "$file")"
  cleaned="$(python3 "${FILTER}" clean < "$file")"
  restored="$(printf '%s' "$cleaned" | python3 "${FILTER}" smudge)"
  if [[ "$restored" != "$original" ]]; then
    echo "--- original ---" >&2
    cat "$file" >&2
    echo "--- cleaned ---" >&2
    printf '%s\n' "$cleaned" >&2
    echo "--- restored ---" >&2
    printf '%s\n' "$restored" >&2
    fail "mismatch for $(basename "$file")"
  fi
  echo "OK roundtrip: $(basename "$file")"
}

# Password + IP + CIDR
roundtrip_file "${FIXTURES}/roundtrip.yaml"

# JSON quoted password + IP
roundtrip_file "${FIXTURES}/config.json"

# TLS block scalar (body replaced on clean, restored on smudge)
original_tls="$(cat "${FIXTURES}/tls-block.yaml")"
cleaned_tls="$(python3 "${FILTER}" clean < "${FIXTURES}/tls-block.yaml")"
if grep -q "BEGIN CERTIFICATE" <<<"$cleaned_tls"; then
  echo "--- cleaned tls ---" >&2
  printf '%s\n' "$cleaned_tls" >&2
  fail "tls-block.yaml PEM body still present after clean"
fi
if ! grep -q "DUMMY_SEC_" <<<"$cleaned_tls"; then
  fail "tls-block.yaml missing dummy token after clean"
fi
restored_tls="$(printf '%s' "$cleaned_tls" | python3 "${FILTER}" smudge)"
if [[ "$restored_tls" != "$original_tls" ]]; then
  echo "--- original tls ---" >&2
  printf '%s\n' "$original_tls" >&2
  echo "--- restored tls ---" >&2
  printf '%s\n' "$restored_tls" >&2
  fail "tls-block.yaml smudge mismatch"
fi
echo "OK roundtrip: tls-block.yaml (block scalar)"

echo "All roundtrip tests passed."
