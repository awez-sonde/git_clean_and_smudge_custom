#!/usr/bin/env python3
"""
Git clean/smudge filter — sanitize secrets before Git, restore on checkout.

Modes:
  clean  — actual → dummy (staging)
  smudge — dummy → actual (checkout)

Mapping: local_secrets_map.json (gitignored). Optional auto-cache:
  local_secrets_learned.json (gitignored) for values detected by field rules.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MAP_FILENAME = "local_secrets_map.json"
DEFAULT_LEARNED_FILENAME = "local_secrets_learned.json"
MAP_ENV_VAR = "GIT_SECRETS_MAP"
LEARNED_ENV_VAR = "GIT_SECRETS_LEARNED"

# IPv4 and CIDR (e.g. 192.168.50.0/24)
_IPV4_OCTET = r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
IPV4_RE = re.compile(rf"\b(?:{_IPV4_OCTET}\.){{3}}{_IPV4_OCTET}\b")
CIDR_RE = re.compile(
    rf"\b(?:{_IPV4_OCTET}\.){{3}}{_IPV4_OCTET}/(?:[0-9]|[1-2][0-9]|3[0-2])\b"
)
EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# key: value  |  key = value  |  key: "value"  (YAML, properties, .env)
FIELD_LINE_RE = re.compile(
    r"^(\s*)([A-Za-z0-9_.-]+)(\s*[:=]\s*)"
    r"(?:\"([^\"]*)\"|'([^']*)'|(\S+))\s*(#.*)?$"
)

# OpenShift / Kubernetes:  - name: DATABASE_PASSWORD
K8S_ENV_NAME_RE = re.compile(
    r"^(\s*)- name:\s*(?:\"([^\"]*)\"|'([^']*)'|(\S+))\s*(#.*)?$"
)

# Case-insensitive substring match on YAML/env KEY names (not hard-coded service names).
# Covers OpenStack (TripleO), OpenShift/K8s, LDAP, auth endpoints, registry creds, etc.
DEFAULT_KEY_SUBSTRINGS = (
    # Passwords & passphrases
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "htpasswd",
    # Secrets & tokens
    "secret",
    "token",
    "credential",
    "bearer",
    "jwt",
    "oauth",
    # API / access keys
    "apikey",
    "api_key",
    "accesskey",
    "access_key",
    "secretkey",
    "secret_key",
    "privatekey",
    "private_key",
    "privkey",
    "clientsecret",
    "client_secret",
    # Admin, LDAP, auth (OpenStack identity / bind / URLs)
    "admin",
    "user",
    "ldap",
    "bind",
    "auth",
    # Registry & image pull (OpenShift)
    "registry",
    "pullsecret",
    "pull_secret",
    "dockerconfig",
    # Crypto / TLS material often holding sensitive blobs
    "keystore",
    "truststore",
    "sshkey",
    "ssh_key",
    "signing",
    "encryption",
    "salt",
    "certificate",
    "cacert",
    "ca_cert",
    "tls",
    # DB / connection strings (when key name includes these words)
    "connstring",
    "connectionstring",
    "connection_string",
    "license",
)

# Optional exact key names (in addition to substring rules)
DEFAULT_SENSITIVE_KEYS: frozenset[str] = frozenset()

# Sanitize "value:" when the preceding "- name:" matches sensitive key rules
K8S_VALUE_KEY = "value"


@dataclass
class SubnetRule:
    actual_cidr: str
    dummy_cidr: str

    def __post_init__(self) -> None:
        self.actual_net = ipaddress.ip_network(self.actual_cidr, strict=False)
        self.dummy_net = ipaddress.ip_network(self.dummy_cidr, strict=False)
        if self.actual_net.prefixlen != self.dummy_net.prefixlen:
            raise ValueError(
                f"subnet rule {self.actual_cidr} → {self.dummy_cidr}: "
                "prefix lengths must match"
            )


@dataclass
class EmailDomainRule:
    actual_domains: list[str]
    dummy_domain: str

    def __post_init__(self) -> None:
        self.actual_domains = [d.lower().strip() for d in self.actual_domains]
        self.dummy_domain = self.dummy_domain.lower().strip()


@dataclass
class SensitiveFields:
    """Match config keys by substring (password in keystone_password) and/or exact name."""

    keys: frozenset[str] = field(default_factory=lambda: DEFAULT_SENSITIVE_KEYS)
    key_substrings: tuple[str, ...] = field(default_factory=lambda: DEFAULT_KEY_SUBSTRINGS)
    match_mode: str = "contains"  # contains | exact | both
    dummy_prefix: str = "DUMMY_SEC_"
    token_length: int = 12


@dataclass
class SanitizeConfig:
    replacements: list[tuple[str, str]]
    subnet_rules: list[SubnetRule]
    email_rules: list[EmailDomainRule]
    sensitive_fields: SensitiveFields | None
    auto_learn: bool
    salt: str


def _repo_root() -> Path | None:
    work_tree = os.environ.get("GIT_WORK_TREE")
    if work_tree:
        return Path(work_tree).resolve()
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return Path(out.stdout.strip()).resolve()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None


def map_path() -> Path:
    explicit = os.environ.get(MAP_ENV_VAR)
    if explicit:
        return Path(explicit).expanduser().resolve()
    root = _repo_root()
    if root is not None:
        return root / DEFAULT_MAP_FILENAME
    return Path.cwd() / DEFAULT_MAP_FILENAME


def learned_path() -> Path:
    explicit = os.environ.get(LEARNED_ENV_VAR)
    if explicit:
        return Path(explicit).expanduser().resolve()
    root = _repo_root()
    if root is not None:
        return root / DEFAULT_LEARNED_FILENAME
    return Path.cwd() / DEFAULT_LEARNED_FILENAME


def load_learned(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    learned = data.get("learned", data)
    if not isinstance(learned, dict):
        raise ValueError("learned file must contain a 'learned' object")
    return {str(k): str(v) for k, v in learned.items()}


def save_learned(path: Path, learned: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": 1, "learned": dict(sorted(learned.items()))}
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def load_config(path: Path) -> SanitizeConfig:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    replacements: list[tuple[str, str]] = []
    for i, item in enumerate(data.get("replacements", [])):
        if not isinstance(item, dict):
            raise ValueError(f"replacements[{i}] must be an object")
        actual, dummy = item.get("actual"), item.get("dummy")
        if not actual or not dummy:
            raise ValueError(f"replacements[{i}] requires 'actual' and 'dummy'")
        if actual == dummy:
            raise ValueError(f"replacements[{i}]: actual and dummy must differ")
        replacements.append((str(actual), str(dummy)))

    subnet_rules: list[SubnetRule] = []
    for i, item in enumerate(data.get("subnet_rules", [])):
        if not isinstance(item, dict):
            raise ValueError(f"subnet_rules[{i}] must be an object")
        actual_cidr = item.get("actual_cidr")
        dummy_cidr = item.get("dummy_cidr")
        if not actual_cidr or not dummy_cidr:
            raise ValueError(f"subnet_rules[{i}] requires actual_cidr and dummy_cidr")
        subnet_rules.append(SubnetRule(str(actual_cidr), str(dummy_cidr)))

    email_rules: list[EmailDomainRule] = []
    for i, item in enumerate(data.get("email_domains", [])):
        if not isinstance(item, dict):
            raise ValueError(f"email_domains[{i}] must be an object")
        domains = item.get("actual_domains") or item.get("domains")
        dummy_domain = item.get("dummy_domain")
        if not domains or not dummy_domain:
            raise ValueError(
                f"email_domains[{i}] requires actual_domains and dummy_domain"
            )
        email_rules.append(EmailDomainRule(list(domains), str(dummy_domain)))

    sensitive_fields: SensitiveFields | None = None
    sf = data.get("sensitive_fields")
    if sf is not False and sf is not None:
        if sf is True:
            sensitive_fields = SensitiveFields()
        elif isinstance(sf, dict):
            keys = sf.get("keys")
            key_set = (
                frozenset(k.lower().replace("-", "_") for k in keys)
                if keys is not None
                else DEFAULT_SENSITIVE_KEYS
            )
            subs = sf.get("key_substrings")
            if subs is not None:
                key_substrings = tuple(
                    s.lower().replace("-", "_") for s in subs if str(s).strip()
                )
            else:
                key_substrings = DEFAULT_KEY_SUBSTRINGS
            match_mode = str(sf.get("match_mode", "contains")).lower()
            if match_mode not in ("contains", "exact", "both"):
                raise ValueError("sensitive_fields.match_mode must be contains, exact, or both")
            sensitive_fields = SensitiveFields(
                keys=key_set,
                key_substrings=key_substrings,
                match_mode=match_mode,
                dummy_prefix=str(sf.get("dummy_prefix", "DUMMY_SEC_")),
                token_length=int(sf.get("token_length", 12)),
            )

    return SanitizeConfig(
        replacements=replacements,
        subnet_rules=subnet_rules,
        email_rules=email_rules,
        sensitive_fields=sensitive_fields,
        auto_learn=bool(data.get("auto_learn", True)),
        salt=str(data.get("salt", "change-me-in-local_secrets_map.json")),
    )


def _map_ip_between_networks(
    ip: ipaddress.IPv4Address,
    src_net: ipaddress.IPv4Network,
    dst_net: ipaddress.IPv4Network,
) -> str | None:
    if ip not in src_net:
        return None
    offset = int(ip) - int(src_net.network_address)
    mapped = dst_net.network_address + offset
    if mapped not in dst_net:
        return None
    return str(mapped)


def apply_subnet_rules(text: str, rules: list[SubnetRule], *, reverse: bool) -> str:
    if not rules:
        return text

    def map_ip_string(ip_str: str) -> str:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return ip_str
        if not isinstance(ip, ipaddress.IPv4Address):
            return ip_str
        for rule in rules:
            if reverse:
                mapped = _map_ip_between_networks(ip, rule.dummy_net, rule.actual_net)
            else:
                mapped = _map_ip_between_networks(ip, rule.actual_net, rule.dummy_net)
            if mapped is not None:
                return mapped
        return ip_str

    def map_cidr_string(cidr_str: str) -> str:
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
        except ValueError:
            return cidr_str
        if not isinstance(net, ipaddress.IPv4Network):
            return cidr_str
        for rule in rules:
            src = rule.dummy_net if reverse else rule.actual_net
            dst = rule.actual_net if reverse else rule.dummy_net
            if net.network_address == src.network_address and net.prefixlen == src.prefixlen:
                return f"{dst.network_address}/{dst.prefixlen}"
        return cidr_str

    def repl_cidr(match: re.Match[str]) -> str:
        return map_cidr_string(match.group(0))

    def repl_ip(match: re.Match[str]) -> str:
        return map_ip_string(match.group(0))

    # CIDR first so we do not partially rewrite network addresses inside CIDRs
    text = CIDR_RE.sub(repl_cidr, text)
    text = IPV4_RE.sub(repl_ip, text)
    return text


def _swap_email_domain(email: str, rule: EmailDomainRule, *, reverse: bool) -> str | None:
    local, _, domain = email.partition("@")
    domain = domain.lower()
    if reverse:
        if domain == rule.dummy_domain:
            for actual in rule.actual_domains:
                return f"{local}@{actual}"
        return None
    if domain in rule.actual_domains:
        return f"{local}@{rule.dummy_domain}"
    return None


def _swap_hostname_domain(hostname: str, rule: EmailDomainRule, *, reverse: bool) -> str | None:
    """OpenShift Route / ingress hosts (no @): app.customer.example → app.dummy.example"""
    host = hostname.lower()
    if reverse:
        dummy = rule.dummy_domain.lower()
        if host == dummy:
            return rule.actual_domains[0]
        suffix = "." + dummy
        if host.endswith(suffix):
            prefix = hostname[: len(hostname) - len(suffix)]
            return f"{prefix}.{rule.actual_domains[0]}"
        return None
    for actual in rule.actual_domains:
        actual_lower = actual.lower()
        if host == actual_lower:
            return rule.dummy_domain
        suffix = "." + actual_lower
        if host.endswith(suffix):
            prefix = hostname[: len(hostname) - len(suffix)]
            return f"{prefix}.{rule.dummy_domain}"
    return None


def apply_email_domain_rules(
    text: str, rules: list[EmailDomainRule], *, reverse: bool
) -> str:
    if not rules:
        return text

    def repl_email(match: re.Match[str]) -> str:
        email = match.group(0)
        for rule in rules:
            swapped = _swap_email_domain(email, rule, reverse=reverse)
            if swapped is not None:
                return swapped
        return email

    text = EMAIL_RE.sub(repl_email, text)

    # Hostnames in YAML (spec.host, URLs) — same email_domains config
    def repl_host(match: re.Match[str]) -> str:
        host = match.group(0)
        if "@" in host:
            return host
        for rule in rules:
            swapped = _swap_hostname_domain(host, rule, reverse=reverse)
            if swapped is not None:
                return swapped
        return host

    return HOSTNAME_RE.sub(repl_host, text)


# FQDN-like tokens (Route hosts, service DNS); requires at least two labels
HOSTNAME_RE = re.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\b"
)


def secret_token(actual: str, cfg: SensitiveFields, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:{actual}".encode()).hexdigest()
    return f"{cfg.dummy_prefix}{digest[: cfg.token_length]}"


def _k8s_env_name_from_match(groups: tuple) -> str:
    _, dq, sq, bare, _comment = groups
    return dq if dq is not None else (sq if sq is not None else (bare or ""))


def _normalize_key_name(name: str) -> str:
    return name.lower().replace("-", "_")


def _is_sensitive_key_name(name: str, cfg: SensitiveFields) -> bool:
    """True if a YAML/env key should be treated as a secret (case-insensitive)."""
    if not name:
        return False
    normalized = _normalize_key_name(name)

    if cfg.match_mode in ("exact", "both") and cfg.keys:
        if normalized in cfg.keys:
            return True

    if cfg.match_mode in ("contains", "both") and cfg.key_substrings:
        return any(sub in normalized for sub in cfg.key_substrings)

    return False


def _is_sensitive_k8s_env(name: str, cfg: SensitiveFields) -> bool:
    return _is_sensitive_key_name(name, cfg)


def _replace_field_value(
    value: str,
    cfg: SensitiveFields,
    salt: str,
    learned: dict[str, str],
    *,
    reverse: bool,
    auto_learn: bool,
) -> str | None:
    """Return new value if changed, or None if unchanged / should skip."""
    if not value:
        return None

    new_value = value
    if reverse:
        for actual, dummy in learned.items():
            if dummy == value:
                return actual
        if value.startswith(cfg.dummy_prefix):
            return None
        return None

    if value.startswith(cfg.dummy_prefix):
        return None
    if value in learned:
        return learned[value]
    new_value = secret_token(value, cfg, salt)
    if auto_learn:
        learned[value] = new_value
    return new_value


def _render_field_line(
    indent: str,
    key: str,
    sep: str,
    quote: str,
    new_value: str,
    comment: str | None,
    newline: str,
) -> str:
    if quote:
        body = f'{indent}{key}{sep}{quote}{new_value}{quote}'
    else:
        body = f"{indent}{key}{sep}{new_value}"
    if comment:
        body += comment
    return body + newline


def apply_sensitive_field_rules(
    text: str,
    cfg: SensitiveFields,
    salt: str,
    learned: dict[str, str],
    *,
    reverse: bool,
    auto_learn: bool,
) -> tuple[str, dict[str, str]]:
    """Detect secrets in YAML/properties and OpenShift/Kubernetes env blocks."""
    lines_out: list[str] = []
    changed = False
    pending_k8s_env: str | None = None

    for line in text.splitlines(keepends=True):
        newline = ""
        if line.endswith("\n"):
            newline = "\n"
            body = line[:-1]
        elif line.endswith("\r\n"):
            newline = "\r\n"
            body = line[:-2]
        else:
            body = line

        k8s_name = K8S_ENV_NAME_RE.match(body)
        if k8s_name:
            pending_k8s_env = _k8s_env_name_from_match(k8s_name.groups())
            lines_out.append(line)
            continue

        m = FIELD_LINE_RE.match(body)
        if not m:
            pending_k8s_env = None
            lines_out.append(line)
            continue

        indent, key, sep, dq, sq, bare, comment = m.groups()
        key_lower = key.lower()

        if dq is not None:
            value, quote = dq, '"'
        elif sq is not None:
            value, quote = sq, "'"
        else:
            value, quote = bare or "", ""

        sensitive = _is_sensitive_key_name(key, cfg)
        if not sensitive and key_lower == K8S_VALUE_KEY and pending_k8s_env:
            sensitive = _is_sensitive_k8s_env(pending_k8s_env, cfg)

        pending_k8s_env = None

        if not sensitive:
            lines_out.append(line)
            continue

        if key_lower == "email" and "@" in value and not reverse:
            lines_out.append(line)
            continue

        new_value = _replace_field_value(
            value, cfg, salt, learned, reverse=reverse, auto_learn=auto_learn
        )
        if new_value is None or new_value == value:
            lines_out.append(line)
            continue

        changed = True
        lines_out.append(
            _render_field_line(indent, key, sep, quote, new_value, comment, newline)
        )

    return "".join(lines_out), learned if changed or auto_learn else learned


def apply_literal_replacements(
    text: str, pairs: list[tuple[str, str]]
) -> str:
    ordered = sorted(pairs, key=lambda p: len(p[0]), reverse=True)
    for src, dst in ordered:
        text = text.replace(src, dst)
    return text


def transform(
    text: str,
    config: SanitizeConfig,
    learned: dict[str, str],
    *,
    reverse: bool,
) -> tuple[str, dict[str, str]]:
    if reverse:
        if config.sensitive_fields:
            text, learned = apply_sensitive_field_rules(
                text,
                config.sensitive_fields,
                config.salt,
                learned,
                reverse=True,
                auto_learn=False,
            )
        text = apply_email_domain_rules(text, config.email_rules, reverse=True)
        text = apply_subnet_rules(text, config.subnet_rules, reverse=True)
        inverted = [(d, a) for a, d in config.replacements]
        text = apply_literal_replacements(text, inverted)
    else:
        text = apply_literal_replacements(text, config.replacements)
        text = apply_subnet_rules(text, config.subnet_rules, reverse=False)
        text = apply_email_domain_rules(text, config.email_rules, reverse=False)
        if config.sensitive_fields:
            text, learned = apply_sensitive_field_rules(
                text,
                config.sensitive_fields,
                config.salt,
                learned,
                reverse=False,
                auto_learn=config.auto_learn,
            )
    return text, learned


def read_stdin() -> str:
    return sys.stdin.buffer.read().decode("utf-8")


def write_stdout(text: str) -> None:
    sys.stdout.buffer.write(text.encode("utf-8"))


def run_clean() -> int:
    path = map_path()
    content = read_stdin()

    if not path.is_file():
        print(
            f"sanitize_filter (clean): mapping file not found: {path}\n"
            "Refusing to stage — create the mapping file or set GIT_SECRETS_MAP.\n"
            "This prevents accidentally committing real secrets.",
            file=sys.stderr,
        )
        return 1

    try:
        config = load_config(path)
        learned = load_learned(learned_path())
        content, learned = transform(content, config, learned, reverse=False)
        if config.auto_learn and config.sensitive_fields:
            save_learned(learned_path(), learned)
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        print(f"sanitize_filter (clean): invalid config: {exc}", file=sys.stderr)
        return 1

    write_stdout(content)
    return 0


def run_smudge() -> int:
    path = map_path()
    content = read_stdin()

    if not path.is_file():
        print(
            f"sanitize_filter (smudge): mapping file not found: {path}\n"
            "Passing repository content through unchanged (dummy placeholders remain).\n"
            "Restore local_secrets_map.json from your secure backup to get real values.",
            file=sys.stderr,
        )
        write_stdout(content)
        return 0

    try:
        config = load_config(path)
        learned_path_ = learned_path()
        learned = load_learned(learned_path_) if learned_path_.is_file() else {}
        content, _ = transform(content, config, learned, reverse=True)
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        print(
            f"sanitize_filter (smudge): invalid config: {exc}\n"
            "Passing content through unchanged.",
            file=sys.stderr,
        )
        write_stdout(content)
        return 0

    write_stdout(content)
    return 0


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("clean", "smudge"):
        print("Usage: sanitize_filter.py clean|smudge", file=sys.stderr)
        return 2
    return run_clean() if sys.argv[1] == "clean" else run_smudge()


if __name__ == "__main__":
    sys.exit(main())
