"""Shared paths, patterns, and subnet discovery for the Git sanitization filter."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

# Primary config filenames (new)
CONFIG_FILENAME = "sanitization.json"
CONFIG_EXAMPLE_FILENAME = "sanitization.json.example"
LEARNED_FILENAME = "sanitization.learned.json"

# Legacy names (still supported for existing clones)
LEGACY_CONFIG_FILENAMES = ("local_secrets_map.json",)
LEGACY_LEARNED_FILENAMES = ("local_secrets_learned.json",)
LEGACY_CONFIG_EXAMPLE = "local_secrets_map.json.example"

CONFIG_ENV_VAR = "SANITIZATION_CONFIG"
LEARNED_ENV_VAR = "SANITIZATION_LEARNED"
LEGACY_CONFIG_ENV_VAR = "GIT_SECRETS_MAP"
LEGACY_LEARNED_ENV_VAR = "GIT_SECRETS_LEARNED"

DEFAULT_SALT = "change-me-to-a-random-string"

SCAN_EXTENSIONS = frozenset(
    {".yaml", ".yml", ".conf", ".config", ".ini", ".properties", ".env", ".json", ".toml"}
)
SKIP_DIR_NAMES = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__"})

_IPV4_OCTET = r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
# Not preceded/followed by digit or dot — avoids helm-3.14.2, v1.21.0 (finding 7)
IPV4_RE = re.compile(
    rf"(?<![0-9.])(?:{_IPV4_OCTET}\.){{3}}{_IPV4_OCTET}(?![0-9.])"
)
CIDR_RE = re.compile(
    rf"(?<![0-9.])(?:{_IPV4_OCTET}\.){{3}}{_IPV4_OCTET}/(?:[0-9]|[1-2][0-9]|3[0-2])(?![0-9.])"
)
HOSTNAME_RE = re.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\b"
)

# Lines like "version: 4.18.0.1" — IP-like token is not a customer network
VERSION_CONTEXT_LINE_RE = re.compile(
    r"^\s*(?:version|app[_\s]?version|kube[_\s]?version|release)\s*[:=]",
    re.IGNORECASE,
)

# RFC 5737 documentation ranges (preferred dummy space)
RESERVED_DUMMY_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

# RFC 6598 shared address space, then 10/8 only if documentation/CGNAT pools exhaust
RFC6598_DUMMY_POOL = ipaddress.ip_network("100.64.0.0/10")
FALLBACK_DUMMY_POOL = ipaddress.ip_network("10.0.0.0/8")

DEFAULT_DUMMY_ADDRESS_POOLS: tuple[ipaddress.IPv4Network, ...] = (
    *RESERVED_DUMMY_NETS,
    RFC6598_DUMMY_POOL,
    FALLBACK_DUMMY_POOL,
)


def resolve_config_path(
    repo_root: Path,
    explicit: str | None = None,
    *,
    must_exist: bool = False,
) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        return path if not must_exist or path.is_file() else None
    for name in (CONFIG_FILENAME, *LEGACY_CONFIG_FILENAMES):
        path = repo_root / name
        if path.is_file():
            return path
    default = repo_root / CONFIG_FILENAME
    return default if not must_exist else None


def resolve_learned_path(repo_root: Path, explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    for name in (LEARNED_FILENAME, *LEGACY_LEARNED_FILENAMES):
        path = repo_root / name
        if path.is_file():
            return path
    return repo_root / LEARNED_FILENAME


def _is_routable_customer_net(net: ipaddress.IPv4Network) -> bool:
    if not isinstance(net, ipaddress.IPv4Network):
        return False
    if net.prefixlen < 8:
        return False
    if int(net.network_address) == 0:
        return False
    if net.is_loopback or net.is_link_local or net.is_multicast:
        return False
    return net.is_private or net.is_global


def _ip_on_version_context_line(text: str, ip_str: str) -> bool:
    for line in text.splitlines():
        if ip_str not in line:
            continue
        if VERSION_CONTEXT_LINE_RE.match(line.strip()):
            return True
    return False


def infer_networks_from_text(text: str) -> set[ipaddress.IPv4Network]:
    found: set[ipaddress.IPv4Network] = set()
    for cidr in CIDR_RE.findall(text):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if isinstance(net, ipaddress.IPv4Network) and _is_routable_customer_net(net):
                found.add(net)
        except ValueError:
            continue
    for ip_str in IPV4_RE.findall(text):
        if _ip_on_version_context_line(text, ip_str):
            continue
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if not isinstance(ip, ipaddress.IPv4Address):
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            continue
        if str(ip).startswith("0."):
            continue
        # Bare IPs are bucketed to /24 for discovery; explicit CIDR keeps true prefix length.
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        if _is_routable_customer_net(net):
            found.add(net)
    return found


def _iter_dummy_candidates(
    prefixlen: int,
    address_pools: tuple[ipaddress.IPv4Network, ...],
):
    """Yield same-prefixlen subnets inside each pool (documentation pools first)."""
    for pool in address_pools:
        if prefixlen < pool.prefixlen:
            continue
        if prefixlen == pool.prefixlen:
            yield pool
            continue
        yield from pool.subnets(new_prefix=prefixlen)


def _dummy_candidate_rejected(
    candidate: ipaddress.IPv4Network,
    actual: ipaddress.IPv4Network,
    all_actuals: set[ipaddress.IPv4Network],
    used_dummies: set[ipaddress.IPv4Network],
) -> bool:
    if candidate in used_dummies:
        return True
    if candidate.overlaps(actual):
        return True
    for other_actual in all_actuals:
        if other_actual != actual and candidate.overlaps(other_actual):
            return True
    for used in used_dummies:
        if candidate.overlaps(used):
            return True
    return False


def suggest_dummy_cidr(
    actual: ipaddress.IPv4Network,
    used_dummies: set[ipaddress.IPv4Network],
    all_actuals: set[ipaddress.IPv4Network] | None = None,
    *,
    address_pools: tuple[ipaddress.IPv4Network, ...] | None = None,
) -> ipaddress.IPv4Network:
    """Pick a dummy CIDR with the same prefix length as actual, avoiding all actual nets."""
    if all_actuals is None:
        all_actuals = {actual}
    else:
        all_actuals = set(all_actuals)
    pools = address_pools if address_pools is not None else DEFAULT_DUMMY_ADDRESS_POOLS

    for candidate in _iter_dummy_candidates(actual.prefixlen, pools):
        if _dummy_candidate_rejected(candidate, actual, all_actuals, used_dummies):
            continue
        if candidate.prefixlen != actual.prefixlen:
            raise ValueError(
                f"internal error: dummy {candidate} prefix length "
                f"does not match actual {actual}"
            )
        return candidate
    pool_list = ", ".join(str(p) for p in pools)
    raise ValueError(
        f"Could not assign a non-overlapping dummy /{actual.prefixlen} for actual {actual}. "
        f"No free subnet of the same prefix length remains in dummy pools: {pool_list}. "
        f"Prefixes shorter than /24 cannot use RFC 5737 documentation /24 pools — add a "
        f"manual subnet_rules entry or extend address pools."
    )


def discover_subnet_rules(networks: set[ipaddress.IPv4Network]) -> list[dict[str, str]]:
    ordered = sorted(networks, key=lambda n: (n.prefixlen, int(n.network_address)))
    all_actuals = set(networks)
    used: set[ipaddress.IPv4Network] = set()
    rules: list[dict[str, str]] = []
    for net in ordered:
        dummy = suggest_dummy_cidr(net, used, all_actuals)
        used.add(dummy)
        rules.append(
            {
                "actual_cidr": str(net),
                "dummy_cidr": str(dummy),
                "comment": "auto-discovered",
            }
        )
    return rules


def discover_domains_from_text(text: str) -> set[str]:
    """Find customer DNS zones from FQDNs (e.g. ocp-worker-0.awezlab.local → awezlab.local)."""
    domains: set[str] = set()
    lab_tlds = frozenset({"local", "internal", "lan", "corp"})
    skip_zones = frozenset({"example.invalid", "example.com", "example.net"})
    for host in HOSTNAME_RE.findall(text):
        if "@" in host:
            continue
        parts = host.lower().split(".")
        if len(parts) < 2 or parts[-1] not in lab_tlds:
            continue
        zone = f"{parts[-2]}.{parts[-1]}"
        if len(parts[-2]) < 2 or zone in skip_zones:
            continue
        domains.add(zone)
    return domains


def iter_scan_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        if path.name in {
            CONFIG_FILENAME,
            CONFIG_EXAMPLE_FILENAME,
            LEARNED_FILENAME,
            *LEGACY_CONFIG_FILENAMES,
            LEGACY_CONFIG_EXAMPLE,
            *LEGACY_LEARNED_FILENAMES,
        }:
            continue
        files.append(path)
    return sorted(files)


def scan_repo_for_networks(root: Path) -> set[ipaddress.IPv4Network]:
    networks: set[ipaddress.IPv4Network] = set()
    for path in iter_scan_files(root):
        try:
            networks |= infer_networks_from_text(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return networks


def scan_repo_for_domains(root: Path) -> set[str]:
    domains: set[str] = set()
    for path in iter_scan_files(root):
        try:
            domains |= discover_domains_from_text(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return domains


def merge_subnet_rules(existing: list[dict], discovered: list[dict]) -> list[dict]:
    by_actual: dict[str, dict] = {}
    for rule in existing:
        actual = rule.get("actual_cidr")
        if actual:
            by_actual[str(actual)] = dict(rule)
    for rule in discovered:
        actual = rule["actual_cidr"]
        if actual not in by_actual:
            by_actual[actual] = rule
    return sorted(by_actual.values(), key=lambda r: r["actual_cidr"])


def merge_email_domains(
    existing: list[dict],
    discovered_domains: set[str],
    dummy_domain: str = "example.invalid",
) -> list[dict]:
    if not existing and discovered_domains:
        return [
            {
                "actual_domains": sorted(discovered_domains),
                "dummy_domain": dummy_domain,
                "comment": "auto-discovered",
            }
        ]
    if not existing:
        return []
    merged = [dict(item) for item in existing]
    if discovered_domains and merged:
        current = set(merged[0].get("actual_domains") or [])
        merged[0]["actual_domains"] = sorted(current | discovered_domains)
    return merged


def load_json_config(path: Path) -> dict:
    if path.is_file():
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    return {}


def build_updated_config(repo_root: Path, base: dict | None = None) -> dict:
    config_path = resolve_config_path(repo_root) or repo_root / CONFIG_FILENAME
    base = dict(base or load_json_config(config_path))
    discovered_rules = discover_subnet_rules(scan_repo_for_networks(repo_root))
    domains = scan_repo_for_domains(repo_root)

    base.setdefault("version", 2)
    base.setdefault("salt", DEFAULT_SALT)
    base.setdefault("auto_learn", True)
    base.setdefault("replacements", [])
    base.setdefault("sensitive_fields", {"match_mode": "contains"})
    base["subnet_rules"] = merge_subnet_rules(base.get("subnet_rules") or [], discovered_rules)
    if domains:
        dummy = "example.invalid"
        if base.get("email_domains"):
            dummy = base["email_domains"][0].get("dummy_domain", dummy)
        base["email_domains"] = merge_email_domains(
            base.get("email_domains") or [], domains, dummy_domain=dummy
        )
    elif "email_domains" not in base:
        base["email_domains"] = []
    return base


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
