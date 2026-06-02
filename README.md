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

**Minimum `.gitignore` lines to add:**

```gitignore
local_secrets_map.json
local_secrets_learned.json
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
| **YAML keys** | `password:`, `secret:`, `token:`, … |
| **Route / host domains** | `app.customer-corp.example` → `app.apps.example.com` |
| **OpenShift `env:` blocks** | `- name: DATABASE_PASSWORD` + `value: …` |

Passwords become `DUMMY_SEC_xxxxxxxxxxxx` in Git; the real text is stored in `local_secrets_learned.json`.

---

## OpenShift / Kubernetes YAML

These file types are covered by `*.yaml` / `*.yml` in `.gitattributes`:

- Manifests (`Deployment`, `Service`, `Route`, `ConfigMap`, `Secret`, …)
- Helm / Kustomize output
- Paths like `manifests/`, `openshift/`, `templates/`, `deploy/`

**Supported well**

- IPv4 and CIDR anywhere in the file (subnet rules)
- `stringData:` / `data:`-style lines: `password: mysecret`
- Container env: `- name: MY_PASSWORD` then `value: mysecret`
- Route / ingress `host:` FQDNs (via `email_domains` — works on hostnames, not only emails)

**See examples:** `examples/openshift/`

**Limitations (important)**

- `data:` values that are **base64** are not decoded — prefer `stringData:` for secrets you need sanitized, or keep those files out of Git.
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
  "keys": [
    "password", "secret", "token", "api_key",
    "client-secret", "bind-password", "htpasswd"
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
examples/app-config.yaml
```
