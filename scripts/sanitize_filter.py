#!/usr/bin/env python3
"""
Git clean/smudge filter — sanitize secrets before Git, restore on checkout.

Modes:
  clean  — actual → dummy (staging)
  smudge — dummy → actual (checkout)

Mapping: sanitization.json (gitignored). Optional cache:
  sanitization.learned.json (gitignored) for values detected by field rules.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sanitize_common import (  # noqa: E402
    CIDR_RE,
    CONFIG_ENV_VAR,
    CONFIG_FILENAME,
    DEFAULT_SALT,
    HOSTNAME_RE,
    IPV4_RE,
    LEARNED_ENV_VAR,
    LEARNED_FILENAME,
    LEGACY_CONFIG_ENV_VAR,
    LEGACY_LEARNED_ENV_VAR,
    resolve_config_path,
    resolve_learned_path,
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

# YAML block scalar: |, |-, |+, |2, >, >-, etc. (indicator + optional digit + optional +|-)
BLOCK_SCALAR_START_RE = re.compile(
    r"^(\s*)([A-Za-z0-9_.-]+)(\s*:\s*)"
    r"([|>]\d*(?:[+-])?)\s*(#.*)?$"
)

# JSON double-quoted key/string value
JSON_STRING_PAIR_RE = re.compile(
    r'"((?:[^"\\]|\\.)*)"\s*:\s*"((?:[^"\\]|\\.)*)"(\s*,)?'
)

# JSON non-string scalars for sensitive keys
JSON_SCALAR_PAIR_RE = re.compile(
    r'"((?:[^"\\]|\\.)*)"\s*:\s*'
    r"(null|true|false|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)"
    r"(\s*,)?",
    re.IGNORECASE,
)

JSON_LEARNED_PREFIX = "__json__"

# Hostname rewrite only on value side of these keys
HOST_VALUE_KEY_RE = re.compile(
    r"^(\s*(?:host|hostname|server|endpoint|url)\s*:\s*)(.*)$",
    re.IGNORECASE,
)

QUOTED_STRING_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')

# Simple substring hits (always checked)
BUILTIN_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "htpasswd",
    "secret",
    "token",
    "credential",
    "bearer",
    "jwt",
    "oauth",
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
    "username",
    "admin_pass",
    "ldap",
    "auth_token",
    "auth_key",
    "registry_password",
    "registry_token",
    "registry_secret",
    "pullsecret",
    "pull_secret",
    "dockerconfig",
    "keystore",
    "truststore",
    "sshkey",
    "ssh_key",
    "certificate",
    "cacert",
    "ca_cert",
    "connstring",
    "connectionstring",
    "connection_string",
)

DEFAULT_KEY_SUBSTRINGS = BUILTIN_KEY_SUBSTRINGS

DEFAULT_SENSITIVE_KEYS: frozenset[str] = frozenset()
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
    keys: frozenset[str] = field(default_factory=lambda: DEFAULT_SENSITIVE_KEYS)
    key_substrings: tuple[str, ...] = field(default_factory=lambda: DEFAULT_KEY_SUBSTRINGS)
    match_mode: str = "contains"
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


def _config_env_path() -> str | None:
    return os.environ.get(CONFIG_ENV_VAR) or os.environ.get(LEGACY_CONFIG_ENV_VAR)


def _learned_env_path() -> str | None:
    return os.environ.get(LEARNED_ENV_VAR) or os.environ.get(LEGACY_LEARNED_ENV_VAR)


def map_path() -> Path:
    explicit = _config_env_path()
    if explicit:
        return Path(explicit).expanduser().resolve()
    root = _repo_root() or Path.cwd()
    return resolve_config_path(root) or root / CONFIG_FILENAME


def learned_path() -> Path:
    explicit = _learned_env_path()
    root = _repo_root() or Path.cwd()
    return resolve_learned_path(root, explicit)


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
    fd, tmp_path = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    tmp = Path(tmp_path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def _validate_dummy_subnet_overlap(rules: list[SubnetRule]) -> None:
    for i, a in enumerate(rules):
        for b in rules[i + 1 :]:
            if a.dummy_net.overlaps(b.dummy_net):
                raise ValueError(
                    f"subnet_rules dummy CIDRs overlap: {a.dummy_cidr} and {b.dummy_cidr}"
                )


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
    _validate_dummy_subnet_overlap(subnet_rules)

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
        salt=str(data.get("salt", DEFAULT_SALT)),
    )


def _load_context() -> tuple[SanitizeConfig, dict[str, str], Path, Path]:
    config_path = map_path()
    learned_p = learned_path()
    if not config_path.is_file():
        raise FileNotFoundError(str(config_path))
    config = load_config(config_path)
    learned = load_learned(learned_p)
    return config, learned, config_path, learned_p


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


def _swap_hostnames_in_fragment(fragment: str, rules: list[EmailDomainRule], *, reverse: bool) -> str:
    def repl_host(match: re.Match[str]) -> str:
        host = match.group(0)
        if "@" in host:
            return host
        for rule in rules:
            swapped = _swap_hostname_domain(host, rule, reverse=reverse)
            if swapped is not None:
                return swapped
        return host

    return HOSTNAME_RE.sub(repl_host, fragment)


def _apply_hostnames_in_quoted_strings(line: str, rules: list[EmailDomainRule], *, reverse: bool) -> str:
    def repl_quoted(match: re.Match[str]) -> str:
        inner = match.group(1)
        swapped = _swap_hostnames_in_fragment(inner, rules, reverse=reverse)
        return f'"{swapped}"'

    return QUOTED_STRING_RE.sub(repl_quoted, line)


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

    lines_out: list[str] = []
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

        host_m = HOST_VALUE_KEY_RE.match(body)
        if host_m:
            prefix, value = host_m.groups()
            value = _swap_hostnames_in_fragment(value, rules, reverse=reverse)
            body = prefix + value
        else:
            body = _apply_hostnames_in_quoted_strings(body, rules, reverse=reverse)

        lines_out.append(body + newline)

    return "".join(lines_out)


def secret_token(actual: str, cfg: SensitiveFields, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:{actual}".encode()).hexdigest()
    return f"{cfg.dummy_prefix}{digest[: cfg.token_length]}"


def _k8s_env_name_from_match(groups: tuple) -> str:
    _, dq, sq, bare, _comment = groups
    return dq if dq is not None else (sq if sq is not None else (bare or ""))


def _normalize_field_key(name: str) -> str:
    return name.lower().replace("-", "_").replace(".", "_")


def _matches_sensitive_key(normalized: str) -> bool:
    """Tight key matching — avoids tls_enabled, registry: URL, bare bind/signing/license."""
    for sub in BUILTIN_KEY_SUBSTRINGS:
        if sub in normalized:
            return True
    if re.search(
        r"(?:^|_)(?:tls[_]?(?:key|crt|cert|certificate|pem|priv|private|ca)"
        r"|(?:key|crt|cert|pem|priv|private|ca)[_]tls)(?:_|$)",
        normalized,
    ):
        return True
    if re.search(
        r"(?:signing|encryption)[_]?(?:key|secret|password|token)"
        r"|(?:key|secret|password|token)[_]?(?:signing|encryption)",
        normalized,
    ):
        return True
    if re.search(
        r"license[_]?(?:key|secret|password|token)"
        r"|(?:key|secret|password|token)[_]?license",
        normalized,
    ):
        return True
    return False


def _is_sensitive_key_name(name: str, cfg: SensitiveFields) -> bool:
    if not name:
        return False
    normalized = _normalize_field_key(name)

    if cfg.match_mode in ("exact", "both") and cfg.keys:
        if normalized in cfg.keys:
            return True

    if cfg.match_mode in ("contains", "both"):
        if _matches_sensitive_key(normalized):
            return True
        if cfg.key_substrings:
            return any(sub in normalized for sub in cfg.key_substrings)

    return False


def _json_learned_key(kind: str, actual: str) -> str:
    return f"{JSON_LEARNED_PREFIX}{kind}__{actual}"


def _lookup_learned_by_dummy(
    dummy: str, learned: dict[str, str]
) -> tuple[str | None, str | None]:
    """Return (restored_literal, json_kind). json_kind None for plain string secrets."""
    for actual_key, mapped_dummy in learned.items():
        if mapped_dummy != dummy:
            continue
        if actual_key.startswith(JSON_LEARNED_PREFIX):
            rest = actual_key[len(JSON_LEARNED_PREFIX) :]
            kind, _, literal = rest.partition("__")
            if kind and literal:
                return literal, kind
        return actual_key, None
    return None, None


def _replace_field_value(
    value: str,
    cfg: SensitiveFields,
    salt: str,
    learned: dict[str, str],
    *,
    reverse: bool,
    auto_learn: bool,
) -> tuple[str | None, bool]:
    """Return (new_value, learned_dirty). learned_dirty True only when a NEW mapping is added."""
    if not value:
        return None, False

    if reverse:
        restored, _json_kind = _lookup_learned_by_dummy(value, learned)
        if restored is not None:
            return restored, False
        if value.startswith(cfg.dummy_prefix):
            return None, False
        return None, False

    if value.startswith(cfg.dummy_prefix):
        return None, False
    if value in learned:
        return learned[value], False
    new_value = secret_token(value, cfg, salt)
    if auto_learn:
        learned[value] = new_value
        return new_value, True
    return new_value, False


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


def _split_line(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n"):
        return line[:-1], "\n"
    return line, ""


def _indent_width(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _block_body_text(body_lines: list[str], content_indent: int) -> str:
    """Block body for learned map — preserves blank lines between PEM blocks."""
    parts: list[str] = []
    for line in body_lines:
        body, _ = _split_line(line)
        if not body.strip():
            parts.append("")
        elif len(body) >= content_indent:
            parts.append(body[content_indent:])
        else:
            parts.append(body.strip())
    return "\n".join(parts)


def _emit_block_body_lines(
    block_text: str, pad: str, newline: str, lines_out: list[str]
) -> None:
    for ln in block_text.split("\n"):
        if ln == "":
            lines_out.append(newline)
        else:
            lines_out.append(f"{pad}{ln}{newline}")


def apply_json_field_rules(
    text: str,
    cfg: SensitiveFields,
    salt: str,
    learned: dict[str, str],
    *,
    reverse: bool,
    auto_learn: bool,
) -> tuple[str, dict[str, str], bool]:
    dirty = False

    def repl_string(match: re.Match[str]) -> str:
        nonlocal dirty
        key, value, comma = match.group(1), match.group(2), match.group(3)
        if not _is_sensitive_key_name(key, cfg):
            return match.group(0)
        if key.lower() == "email" and "@" in value and not reverse:
            return match.group(0)
        if reverse:
            restored, json_kind = _lookup_learned_by_dummy(value, learned)
            if restored is None:
                return match.group(0)
            if json_kind:
                return f'"{key}": {restored}{comma}'
            return f'"{key}": "{restored}"{comma}'
        new_value, entry_dirty = _replace_field_value(
            value, cfg, salt, learned, reverse=reverse, auto_learn=auto_learn
        )
        if entry_dirty:
            dirty = True
        if new_value is None or new_value == value:
            return match.group(0)
        return f'"{key}": "{new_value}"{comma}'

    def repl_scalar(match: re.Match[str]) -> str:
        nonlocal dirty
        key, literal, comma = match.group(1), match.group(2), match.group(3)
        if not _is_sensitive_key_name(key, cfg):
            return match.group(0)
        kind = literal.lower()
        if reverse:
            new_value, entry_dirty = _replace_field_value(
                literal, cfg, salt, learned, reverse=True, auto_learn=False
            )
            if new_value is None:
                return match.group(0)
            return f'"{key}": {new_value}{comma}'
        new_dummy, entry_dirty = _replace_field_value(
            literal, cfg, salt, learned, reverse=False, auto_learn=False
        )
        if new_dummy is None:
            new_dummy = secret_token(literal, cfg, salt)
        if auto_learn:
            jkey = _json_learned_key(kind, literal)
            if learned.get(jkey) != new_dummy:
                learned[jkey] = new_dummy
                dirty = True
        return f'"{key}": "{new_dummy}"{comma}'

    text = JSON_STRING_PAIR_RE.sub(repl_string, text)
    text = JSON_SCALAR_PAIR_RE.sub(repl_scalar, text)
    return text, learned, dirty


def apply_sensitive_field_rules(
    text: str,
    cfg: SensitiveFields,
    salt: str,
    learned: dict[str, str],
    *,
    reverse: bool,
    auto_learn: bool,
) -> tuple[str, dict[str, str], bool]:
    lines = text.splitlines(keepends=True)
    lines_out: list[str] = []
    dirty = False
    pending_k8s_env: str | None = None
    i = 0

    while i < len(lines):
        line = lines[i]
        body, newline = _split_line(line)

        k8s_name = K8S_ENV_NAME_RE.match(body)
        if k8s_name:
            pending_k8s_env = _k8s_env_name_from_match(k8s_name.groups())
            lines_out.append(line)
            i += 1
            continue

        block_m = BLOCK_SCALAR_START_RE.match(body)
        if block_m:
            indent, key, sep, marker, comment = block_m.groups()
            if _is_sensitive_key_name(key, cfg):
                base_indent = len(indent)
                body_lines: list[str] = []
                j = i + 1
                while j < len(lines):
                    next_body, _ = _split_line(lines[j])
                    if next_body.strip() == "":
                        body_lines.append(lines[j])
                        j += 1
                        continue
                    if _indent_width(next_body) <= base_indent:
                        break
                    body_lines.append(lines[j])
                    j += 1

                content_indent = base_indent + 2
                block_core = _block_body_text(body_lines, content_indent)

                new_token, entry_dirty = _replace_field_value(
                    block_core,
                    cfg,
                    salt,
                    learned,
                    reverse=reverse,
                    auto_learn=auto_learn,
                )
                if entry_dirty:
                    dirty = True

                if new_token is not None and new_token != block_core:
                    pad = indent + "  "
                    header = f"{indent}{key}{sep}{marker}"
                    if comment:
                        header += comment
                    lines_out.append(header + newline)
                    if reverse:
                        _emit_block_body_lines(new_token, pad, newline, lines_out)
                    else:
                        lines_out.append(f"{pad}{new_token}{newline}")
                    i = j
                    continue

            lines_out.append(line)
            i += 1
            continue

        m = FIELD_LINE_RE.match(body)
        if not m:
            pending_k8s_env = None
            lines_out.append(line)
            i += 1
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
            sensitive = _is_sensitive_key_name(pending_k8s_env, cfg)

        pending_k8s_env = None

        if not sensitive:
            lines_out.append(line)
            i += 1
            continue

        if key_lower == "email" and "@" in value and not reverse:
            lines_out.append(line)
            i += 1
            continue

        new_value, entry_dirty = _replace_field_value(
            value, cfg, salt, learned, reverse=reverse, auto_learn=auto_learn
        )
        if entry_dirty:
            dirty = True
        if new_value is None or new_value == value:
            lines_out.append(line)
            i += 1
            continue

        lines_out.append(
            _render_field_line(indent, key, sep, quote, new_value, comment, newline)
        )
        i += 1

    return "".join(lines_out), learned, dirty


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
) -> tuple[str, dict[str, str], bool]:
    learned_dirty = False

    if reverse:
        if config.sensitive_fields:
            text, learned, d = apply_json_field_rules(
                text,
                config.sensitive_fields,
                config.salt,
                learned,
                reverse=True,
                auto_learn=False,
            )
            learned_dirty = learned_dirty or d
            text, learned, d = apply_sensitive_field_rules(
                text,
                config.sensitive_fields,
                config.salt,
                learned,
                reverse=True,
                auto_learn=False,
            )
            learned_dirty = learned_dirty or d
        text = apply_email_domain_rules(text, config.email_rules, reverse=True)
        text = apply_subnet_rules(text, config.subnet_rules, reverse=True)
        inverted = [(d, a) for a, d in config.replacements]
        text = apply_literal_replacements(text, inverted)
    else:
        text = apply_literal_replacements(text, config.replacements)
        text = apply_subnet_rules(text, config.subnet_rules, reverse=False)
        text = apply_email_domain_rules(text, config.email_rules, reverse=False)
        if config.sensitive_fields:
            text, learned, d = apply_sensitive_field_rules(
                text,
                config.sensitive_fields,
                config.salt,
                learned,
                reverse=False,
                auto_learn=config.auto_learn,
            )
            learned_dirty = learned_dirty or d
            text, learned, d = apply_json_field_rules(
                text,
                config.sensitive_fields,
                config.salt,
                learned,
                reverse=False,
                auto_learn=config.auto_learn,
            )
            learned_dirty = learned_dirty or d

    return text, learned, learned_dirty


def read_stdin() -> str:
    return sys.stdin.buffer.read().decode("utf-8", errors="surrogateescape")


def write_stdout(text: str) -> None:
    sys.stdout.buffer.write(text.encode("utf-8", errors="surrogateescape"))


def run_clean() -> int:
    content = read_stdin()

    try:
        config, learned, _config_path, learned_p = _load_context()
    except FileNotFoundError as exc:
        print(
            f"sanitize_filter (clean): config not found: {exc}\n"
            f"Refusing to stage — copy {CONFIG_FILENAME}.example to {CONFIG_FILENAME},\n"
            f"or run: python3 scripts/discover_sanitization.py --write\n"
            "This prevents accidentally committing real secrets.",
            file=sys.stderr,
        )
        return 1

    try:
        content, learned, learned_dirty = transform(content, config, learned, reverse=False)
        if learned_dirty:
            save_learned(learned_p, learned)
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        print(f"sanitize_filter (clean): invalid config: {exc}", file=sys.stderr)
        return 1

    write_stdout(content)
    return 0


def run_smudge() -> int:
    content = read_stdin()

    try:
        config, learned, _config_path, _learned_p = _load_context()
    except FileNotFoundError as exc:
        print(
            f"sanitize_filter (smudge): config not found: {exc}\n"
            "Passing repository content through unchanged (dummy placeholders remain).\n"
            f"Restore {CONFIG_FILENAME} and {LEARNED_FILENAME} from your secure backup.",
            file=sys.stderr,
        )
        write_stdout(content)
        return 0

    try:
        content, _, _ = transform(content, config, learned, reverse=True)
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
