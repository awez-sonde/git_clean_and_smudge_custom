# Git secret sanitizer (clean / smudge)

Keep **real** customer IPs and passwords on your laptop. Store **safe dummy values** in Git.

Works with **YAML** (OpenShift, Kubernetes, Helm), plus `.conf`, `.env`, `.properties`, JSON, and more.

---

## What this does 

1. You edit files locally with **real** data (e.g. `192.168.50.11`, real passwords).
2. When you run `git add` / `git commit`, Git runs a **clean** filter → secrets are replaced before they are saved in the repo.
3. When you `git pull` / `git checkout`, a **smudge** filter puts the **real** values back on disk.

Your teammates (or CI) without your private map file only see dummies.

---

## Copy these files into your own repo

To use this in **another** Git repository, copy the items below and commit everything **except** the private map files.

| File / folder | Commit to Git? | Purpose |
|---------------|----------------|---------|
| `scripts/sanitize_filter.py` | **Yes** | The filter program (Python 3) |
| `.gitattributes` | **Yes** | Tells Git which files use the filter (`*.yaml`, `*.yml`, etc.) |
| `local_secrets_map.json.example` | **Yes** | Template for rules (no real secrets) |
| `.gitignore` entries for map files | **Yes** | Stops accidental commit of real secrets |
| `local_secrets_map.json` | **No** — gitignored | **Your** rules (subnets, domains, salt) |
| `local_secrets_learned.json` | **No** — gitignored | Auto-saved passwords from YAML (created on first `git add`) |

**Add the minimum `.gitignore` entries** (run from your repo root):

```bash
# Append both private map files (safe to run more than once if lines already exist)
cat >> .gitignore <<'EOF'
local_secrets_map.json
local_secrets_learned.json
EOF

# Confirm Git will ignore them
git check-ignore -v local_secrets_map.json local_secrets_learned.json
```

If `.gitignore` does not exist yet:

```bash
cat > .gitignore <<'EOF'
local_secrets_map.json
local_secrets_learned.json
EOF
```

**One-time Git setup** (run inside each clone of the repo):

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"
FILTER="${REPO_ROOT}/scripts/sanitize_filter.py"
chmod +x "${FILTER}"

git config --local filter.sanitize-secrets.clean  "python3 ${FILTER} clean"
git config --local filter.sanitize-secrets.smudge "python3 ${FILTER} smudge"
git config --local filter.sanitize-secrets.required true
```

**Per developer machine:**

```bash
cp local_secrets_map.json.example local_secrets_map.json
# Edit: salt, customer subnet, email domains
```

Back up `local_secrets_map.json` and `local_secrets_learned.json` outside Git (password manager, vault, etc.).

---

## What gets rewritten automatically

You configure **rules once** in `local_secrets_map.json`. You do **not** list every IP.

| Rule | Example |
|------|---------|
| **Subnet** | All `192.168.50.x` → `10.0.0.x` in any YAML line |
| **Email / route host domain** | `app.customer-corp.example` → `app.apps.example.com` |
| **YAML / env key names** | Any key whose name **contains** `password`, `secret`, `token`, … (case-insensitive), e.g. `Keystone_Password`, `http_password`, `nova_apiPassword` |
| **Route / host domains** | `app.customer-corp.example` → `app.apps.example.com` |
| **OpenShift `env:` blocks** | `- name: DATABASE_PASSWORD` + `value: …` |

Matched secret **values** become `DUMMY_SEC_xxxxxxxxxxxx` in Git. The real text is stored in **`local_secrets_learned.json`** (auto-updated on `git add`), not in `local_secrets_map.json`. The map file only holds **rules** (subnets, domains, which words to match in key names).

---

## OpenShift / Kubernetes YAML

These file types are covered by `*.yaml` / `*.yml` in `.gitattributes`:

- Manifests (`Deployment`, `Service`, `Route`, `ConfigMap`, `Secret`, …)
- Helm / Kustomize output
- Paths like `manifests/`, `openshift/`, `templates/`, `deploy/`

**Supported well**

- IPv4 and CIDR anywhere in the file (subnet rules)
- Container env: `- name: MY_PASSWORD` then `value: mysecret`
- Route / ingress `host:` FQDNs (via `email_domains` — works on hostnames, not only emails)
- Kubernetes `Secret` manifests using **`stringData:`** (plain text; see below)

**See examples:** `examples/openshift/`

### Use `stringData:` for OpenShift / Kubernetes Secrets

For this filter to rewrite secret values in YAML, use **`stringData`** with normal plain-text values. The filter matches **key names** that contain words like `password` or `secret` (see [Automatic key detection](#automatic-key-detection) below).

**Recommended (works with this tool):**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-credentials
type: Opaque
stringData:
  password: P@ssw0rd!Customer#2024
  api_key: customer-api-key-xyz
```

After `git add`, Git stores dummies (e.g. `password: DUMMY_SEC_77d6ae159093`). Your local file still shows real values after checkout.

**Avoid for filtered manifests:** `data:` with base64 — the filter does **not** decode base64, so real secrets would stay in Git:

```yaml
# Not supported by the filter — do not use this pattern in committed YAML
data:
  password: UGFzc3dvcmQxMjM=   # base64; unchanged by the filter
```

If you must use `data:` in the cluster, generate Secrets outside this repo, or keep those files out of Git.

### Automatic key detection

**Your understanding (updated behaviour):** the filter does **not** only match a key literally named `password`. It matches any field name that **contains** a configured word, **case-insensitive**, including:

| Key in your file | Why matched? |
|------------------|--------------|
| `AdminPassword`, `AodhDatabasePassword` | contains `password` |
| `admin_user` | contains `admin` and `user` |
| `ldap_bind`, `ldap_bind_password` | contains `ldap` / `bind` / `password` |
| `auth_url`, `IdentityAuthURL` | contains `auth` |
| `pull_secret`, `dockerconfigjson` | contains `pull_secret` / `dockerconfig` |
| `cluster_description` | No matching substring |

Default `key_substrings` include OpenStack / OpenShift patterns: `password`, `secret`, `token`, `admin`, `user`, `ldap`, `bind`, `auth`, `registry`, `pull_secret`, `tls`, and more (see `local_secrets_map.json.example`).

Configure or trim words in `local_secrets_map.json`:

```json
"sensitive_fields": {
  "match_mode": "contains",
  "key_substrings": [
    "password", "secret", "token", "admin", "user", "ldap", "bind", "auth"
  ]
}
```

Remove a word from the list if it matches too many keys in your repo (e.g. drop `user` if you only want `admin_user`-style fields via `admin`).

- **`match_mode: "contains"`** (default) — substring match on key names; best for OpenStack / many password fields.
- **`match_mode: "exact"`** — only keys listed in `"keys": ["password", ...]`.
- **`match_mode: "both"`** — substring rules plus exact extras.

**Where values are stored:** on `git add`, new secrets are written to **`local_secrets_learned.json`** (gitignored). You do **not** add each password to `local_secrets_map.json` by hand.

**OpenStack example:** `examples/openstack/allocation.yaml`

### Custom secret types (extra words or exact keys)

Add another substring if your manifests use a special naming pattern:

```json
"key_substrings": ["password", "secret", "licensekey", "ldapbind"]
```

Or exact-only keys:

```json
"match_mode": "exact",
"keys": ["my_special_credential"]
```

Example in `stringData`:

```yaml
stringData:
  keystone_password: real-keystone    # sanitized (contains "password")
  oauthclientsecret: real-oauth       # sanitized (contains "secret")
  description: Customer ACME install  # left unchanged
```

Env vars: `- name: KEYSTONE_PASSWORD` + `value: …` uses the same rules (`examples/openshift/deployment.yaml`).

**Limitations (important)**

- Very complex YAML (multiline `|`, folded blocks) may need manual `replacements` in the map file.
- Add extra `subnet_rules` / `email_domains` for each customer environment.

### Suggested additions to `local_secrets_map.json`

```json
"subnet_rules": [
  { "actual_cidr": "192.168.50.0/24", "dummy_cidr": "10.0.0.0/24" },
  { "actual_cidr": "10.20.0.0/16", "dummy_cidr": "172.16.0.0/16" }
],
"email_domains": [
  {
    "actual_domains": ["customer-corp.example", "cluster.customer.local"],
    "dummy_domain": "apps.example.com"
  }
],
"sensitive_fields": {
  "match_mode": "contains",
  "key_substrings": [
    "password", "secret", "token", "admin", "user", "ldap", "bind", "auth",
    "registry", "pull_secret", "oauth", "tls"
  ]
}
```

Optional **manual** `replacements` for fixed strings (cluster API URL, LDAP DN, etc.).

---

## Quick test

```bash
cp local_secrets_map.json.example local_secrets_map.json

# IP in YAML
printf 'host: 192.168.50.11\n' | python3 scripts/sanitize_filter.py clean

# OpenShift env block
python3 scripts/sanitize_filter.py clean < examples/openshift/deployment.yaml

# OpenStack-style password keys (keystone_password, HTTPPassword, …)
python3 scripts/sanitize_filter.py clean < examples/openstack/allocation.yaml
```

---

## If you already committed secrets

After setup, refresh the index so the clean filter runs:

```bash
git rm --cached -r .
git add .
git commit -m "Apply secret sanitization filter"
```

---

## Security

- Not encryption — anyone with your map + learned files can restore secrets.
- Never commit `local_secrets_map.json` or `local_secrets_learned.json`.
- CI without those files keeps dummy values (usually what you want).

---

## Repo layout

```
scripts/sanitize_filter.py      # filter (required)
.gitattributes                  # file patterns (required)
local_secrets_map.json.example  # template (required)
local_secrets_map.json          # your rules (local only)
local_secrets_learned.json      # auto passwords (local only)
examples/openshift/             # sample YAML
examples/openstack/             # password key auto-detection
examples/app-config.yaml
```
