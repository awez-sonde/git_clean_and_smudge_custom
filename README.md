# Git secret sanitizer (clean / smudge)

Keep **real** customer IPs and passwords on your laptop. Store **safe dummy values** in Git.

Works with **YAML** (OpenShift, Kubernetes, OpenStack), plus `.conf`, `.env`, `.properties`, JSON, and more.

---

## What this does

1. You edit files locally with **real** data.
2. `git add` / `git commit` runs a **clean** filter → dummies go into Git.
3. `git pull` / `git checkout` runs **smudge** → real values return on disk.

---

## Copy into your repo

### Option A — install script (recommended)

From the **sanitizer repo**, run:

```bash
chmod +x scripts/install_sanitization.sh

./scripts/install_sanitization.sh /path/to/your-repo
# or with both paths explicit:
./scripts/install_sanitization.sh /path/to/your-repo /path/to/git_clean_and_smudge_custom
```

The script will:

1. Copy `scripts/sanitize_filter.py`, `sanitize_common.py`, `discover_sanitization.py`
2. Copy `sanitization.json.example` and install `.gitattributes`
3. Append gitignore entries for private config files
4. Configure `git config --local filter.sanitize-secrets.*`
5. Create `sanitization.json` and run `discover_sanitization.py --write`

It **does not** run `git add` or `git commit` — you do that when ready (see script output).

### Option B — manual copy

| File | Commit? | Purpose |
|------|---------|---------|
| `scripts/sanitize_filter.py` | Yes | Filter (Python 3) |
| `scripts/sanitize_common.py` | Yes | Shared config + discovery |
| `scripts/discover_sanitization.py` | Yes | Auto-detect subnets from repo |
| `.gitattributes` | Yes | Which files use the filter |
| `sanitization.json.example` | Yes | Template (no secrets) |
| `sanitization.json` | **No** | Your live config (gitignored) |
| `sanitization.learned.json` | **No** | Auto-saved password map (gitignored) |

**`.gitignore` (run from repo root):**

```bash
cat >> .gitignore <<'EOF'
sanitization.json
sanitization.learned.json
EOF

git check-ignore -v sanitization.json sanitization.learned.json
```

**Git filter (once per clone):**

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"
FILTER="${REPO_ROOT}/scripts/sanitize_filter.py"
chmod +x "${FILTER}" "${REPO_ROOT}/scripts/discover_sanitization.py"

git config --local filter.sanitize-secrets.clean  "python3 ${FILTER} clean"
git config --local filter.sanitize-secrets.smudge "python3 ${FILTER} smudge"
git config --local filter.sanitize-secrets.required true
```

---

## Auto-discover subnets (no manual CIDR list)

Scan all `*.yaml` / config files in the repo, find IPs and CIDRs, and write **`subnet_rules`** into `sanitization.json`:

```bash
# Preview discovered networks
python3 scripts/discover_sanitization.py

# Write sanitization.json (creates or merges with existing rules)
python3 scripts/discover_sanitization.py --write

# Refresh the committed template from current repo content
python3 scripts/discover_sanitization.py --write-example
```

Example output:

```
Scanned /path/to/your-repo
  Networks: 6  Domains: 1
  192.168.10.0/24 → 10.0.10.0/24
  172.17.0.0/24 → 10.0.17.0/24
  10.0.0.0/24 → 10.0.100.0/24
```

- **Merges** with existing rules (won't delete manual entries).
- Assigns dummy CIDRs with the **same prefix length** as each actual, preferring RFC 5737 documentation space (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), then RFC 6598 (`100.64.0.0/10`), then `10.0.0.0/8` only if needed. Dummies never overlap any actual subnet in the config.
- Discovers lab domains like `awezlab.local` from hostnames in YAML.

**Prefix lengths:** A **bare IP** in YAML (e.g. `host: 10.1.2.3`) is discovered as a **/24** network. To discover or sanitize at true size — **/32 host routes**, **/23 supernets**, **/16**, etc. — write an **explicit CIDR** in the file (`10.10.10.5/32`, `192.168.0.0/23`) or add a manual `subnet_rules` entry. The clean/smudge filter supports all prefix lengths from /8 through /32 once a rule exists.

**First-time setup:**

```bash
cp sanitization.json.example sanitization.json
python3 scripts/discover_sanitization.py --write
# Edit salt in sanitization.json, re-run discover after adding new networks
```

Legacy filenames `local_secrets_map.json` still work if you already use them.

---

## Config file: `sanitization.json`

| Section | Purpose |
|---------|---------|
| `subnet_rules` | Actual → dummy CIDR (auto-filled by discover script) |
| `email_domains` | Hostname zones (auto-filled, e.g. `awezlab.local`) |
| `sensitive_fields.key_substrings` | Extra patterns (built-in rules already match `password`, `secret`, `apikey`, …) |
| `salt` | Stable tokens for learned secrets — set once |
| `replacements` | Optional manual one-off strings |

Built-in key matching is **tight**: it targets secret-bearing names (`password`, `registry_password`, `tls.crt`, `tls_key`, …) and does **not** treat plain config like `admin_user`, `auth_url`, `IdentityAuthURL`, `tls_enabled`, or `registry: docker.io` as secrets. Add `key_substrings` only for project-specific secret key names.

Password **values** go to **`sanitization.learned.json`** on `git add`, not into `sanitization.json`.

---

## Sanitize and commit

```bash
python3 scripts/discover_sanitization.py --write   # refresh subnets if needed
git rm --cached -r .
git add .
git commit -m "Sanitize credentials and network ranges"
git push
```

---

## Quick test

```bash
python3 -m unittest tests.test_ip_regex
chmod +x tests/test_roundtrip.sh && ./tests/test_roundtrip.sh

# Password fields → dummies; admin_user / auth_url stay plain text
python3 scripts/sanitize_filter.py clean < examples/openstack/allocation.yaml
```

---

## Repo layout

```
scripts/install_sanitization.sh  # one-command setup into another repo
scripts/sanitize_filter.py
scripts/sanitize_common.py
scripts/discover_sanitization.py
sanitization.json.example      # commit
sanitization.json              # local only
sanitization.learned.json      # local only
.gitattributes
examples/
```

---

## Security

- Not encryption — anyone with `sanitization.json` + `sanitization.learned.json` can restore secrets.
- Re-run `discover_sanitization.py --write` when you add new VLANs to the repo.
- Old commits still contain secrets until history is rewritten.
