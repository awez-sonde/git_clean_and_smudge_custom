#!/usr/bin/env bash
#
# Install Git clean/smudge sanitization into a target repository.
#
# Usage:
#   ./scripts/install_sanitization.sh <target-repo> [sanitizer-repo]
#
# Example:
#   ./scripts/install_sanitization.sh /path/to/your-repo /path/to/git_clean_and_smudge_custom
#
# Stops before git add / commit — run those steps yourself when ready.

set -euo pipefail

GITIGNORE_PATTERNS=(
  "sanitization.json"
  "sanitization.learned.json"
  "local_secrets_map.json"
  "local_secrets_learned.json"
  "scripts/__pycache__/"
)

die() {
  echo "install_sanitization: $*" >&2
  exit 1
}

info() {
  echo "==> $*"
}

usage() {
  sed -n '2,10p' "$0" | tail -n +2
  exit 1
}

[[ $# -ge 1 && $# -le 2 ]] || usage

TARGET="$(cd "$1" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANITIZER="${2:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

[[ -d "$TARGET" ]] || die "Target repo not found: $1"
[[ -d "$SANITIZER" ]] || die "Sanitizer repo not found: ${2:-$SANITIZER}"
[[ -d "$TARGET/.git" ]] || die "Target is not a git repo: $TARGET"

command -v python3 >/dev/null 2>&1 || die "python3 is required"
command -v git >/dev/null 2>&1 || die "git is required"

for f in \
  scripts/sanitize_filter.py \
  scripts/sanitize_common.py \
  scripts/discover_sanitization.py \
  sanitization.json.example \
  .gitattributes
do
  [[ -f "$SANITIZER/$f" ]] || die "Missing in sanitizer repo: $f"
done

info "Target repo:    $TARGET"
info "Sanitizer repo: $SANITIZER"

# --- Copy scripts ---
info "Copying scripts/"
mkdir -p "$TARGET/scripts"
install -m 755 "$SANITIZER/scripts/sanitize_filter.py" "$TARGET/scripts/"
install -m 755 "$SANITIZER/scripts/sanitize_common.py" "$TARGET/scripts/"
install -m 755 "$SANITIZER/scripts/discover_sanitization.py" "$TARGET/scripts/"

# --- Copy template ---
info "Copying sanitization.json.example"
install -m 644 "$SANITIZER/sanitization.json.example" "$TARGET/sanitization.json.example"

# --- .gitattributes ---
if [[ -f "$TARGET/.gitattributes" ]]; then
  if grep -q 'filter=sanitize-secrets' "$TARGET/.gitattributes" 2>/dev/null; then
    info ".gitattributes already configures filter=sanitize-secrets (unchanged)"
  else
    info "Appending sanitization rules to existing .gitattributes"
    {
      echo ""
      echo "# Git secret sanitization (added by install_sanitization.sh)"
      grep -v '^#' "$SANITIZER/.gitattributes" | sed '/^[[:space:]]*$/d'
    } >> "$TARGET/.gitattributes"
  fi
else
  info "Installing .gitattributes"
  install -m 644 "$SANITIZER/.gitattributes" "$TARGET/.gitattributes"
fi

# --- .gitignore ---
info "Updating .gitignore"
touch "$TARGET/.gitignore"
if ! grep -q 'Git secret sanitization' "$TARGET/.gitignore" 2>/dev/null; then
  echo "" >> "$TARGET/.gitignore"
  echo "# Git secret sanitization (added by install_sanitization.sh)" >> "$TARGET/.gitignore"
fi
for pattern in "${GITIGNORE_PATTERNS[@]}"; do
  if ! grep -qxF "$pattern" "$TARGET/.gitignore" 2>/dev/null; then
    echo "$pattern" >> "$TARGET/.gitignore"
  fi
done

if git -C "$TARGET" check-ignore -q sanitization.json 2>/dev/null; then
  info "sanitization.json is gitignored"
else
  die "Failed to gitignore sanitization.json — check $TARGET/.gitignore"
fi

# --- Git filter (local to target repo) ---
info "Configuring git clean/smudge filter"
FILTER="$TARGET/scripts/sanitize_filter.py"
git -C "$TARGET" config --local filter.sanitize-secrets.clean  "python3 ${FILTER} clean"
git -C "$TARGET" config --local filter.sanitize-secrets.smudge "python3 ${FILTER} smudge"
git -C "$TARGET" config --local filter.sanitize-secrets.required true

# --- Local config ---
if [[ -f "$TARGET/sanitization.json" ]]; then
  info "Keeping existing sanitization.json"
else
  info "Creating sanitization.json from example"
  cp "$TARGET/sanitization.json.example" "$TARGET/sanitization.json"
fi

# --- Auto-discover subnets / domains from target repo ---
info "Discovering subnets and domains (sanitization.json)"
(
  cd "$TARGET"
  python3 scripts/discover_sanitization.py --write
)

# --- Quick smoke test ---
info "Smoke test on a YAML file (if present)"
SAMPLE="$(find "$TARGET" -name '*.yaml' -not -path '*/.git/*' 2>/dev/null | head -1 || true)"
if [[ -n "$SAMPLE" ]]; then
  if python3 "$TARGET/scripts/sanitize_filter.py" clean < "$SAMPLE" >/dev/null 2>&1; then
    info "Filter OK: $(basename "$SAMPLE")"
  else
    die "Filter smoke test failed on $SAMPLE"
  fi
else
  info "No YAML found for smoke test (skipped)"
fi

cat <<EOF

Installation complete.

Private files (never commit):
  $TARGET/sanitization.json
  $TARGET/sanitization.learned.json

Optional: edit salt in sanitization.json before your first commit.

Verify manually:
  cd $TARGET
  python3 scripts/sanitize_filter.py clean < examples/openstack/allocation.yaml | head -5
  python3 scripts/discover_sanitization.py          # preview rules

When ready to sanitize and commit (run yourself):
  cd $TARGET
  git rm --cached -r .
  git add .
  git diff --cached --stat
  git commit -m "Sanitize credentials and network ranges"
  git push

EOF
