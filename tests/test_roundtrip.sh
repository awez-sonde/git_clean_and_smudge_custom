#!/usr/bin/env bash
# Round-trip clean → smudge; byte-identical restore (findings 1–5).
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
  if ! diff -u <(printf '%s' "$original") <(printf '%s' "$restored") >/dev/null; then
    echo "--- diff -u $(basename "$file") ---" >&2
    diff -u <(printf '%s' "$original") <(printf '%s' "$restored") >&2 || true
    fail "byte mismatch for $(basename "$file")"
  fi
  echo "OK roundtrip (byte-identical): $(basename "$file")"
}

assert_tls_clean() {
  local file="$1"
  local cleaned
  cleaned="$(python3 "${FILTER}" clean < "$file")"
  if grep -q "BEGIN CERTIFICATE" <<<"$cleaned"; then
    echo "--- cleaned ---" >&2
    printf '%s\n' "$cleaned" >&2
    fail "$(basename "$file"): PEM still present after clean"
  fi
  if ! grep -q "DUMMY_SEC_" <<<"$cleaned"; then
    fail "$(basename "$file"): missing dummy token after clean"
  fi
}

roundtrip_file "${FIXTURES}/roundtrip.yaml"
roundtrip_file "${FIXTURES}/config.json"
roundtrip_file "${FIXTURES}/config-numeric.json"

assert_tls_clean "${FIXTURES}/tls-block.yaml"
roundtrip_file "${FIXTURES}/tls-block.yaml"

assert_tls_clean "${FIXTURES}/tls-block-strip.yaml"
if ! python3 "${FILTER}" clean < "${FIXTURES}/tls-block-strip.yaml" | grep -q "tls.crt: |-"; then
  fail "tls-block-strip.yaml: chomping marker |- not preserved on clean pass-through header"
fi
roundtrip_file "${FIXTURES}/tls-block-strip.yaml"

assert_tls_clean "${FIXTURES}/tls-block-ca-chain.yaml"
roundtrip_file "${FIXTURES}/tls-block-ca-chain.yaml"

# False-positive keys: plain config untouched; secret keys sanitized
fp="${FIXTURES}/false-positive-keys.yaml"
fp_clean="$(python3 "${FILTER}" clean < "$fp")"
grep -q 'tls_enabled: true' <<<"$fp_clean" || fail "tls_enabled was modified"
grep -q 'registry: docker.io' <<<"$fp_clean" || fail "registry URL was modified"
grep -q 'DUMMY_SEC_' <<<"$fp_clean" || fail "registry_password not sanitized"
grep -q 'BEGIN PRIVATE KEY' <<<"$fp_clean" && fail "tls.crt PEM leaked after clean"
roundtrip_file "$fp"

echo "All roundtrip tests passed."
