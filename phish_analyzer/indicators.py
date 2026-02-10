"""Indicator and heuristic checks."""

from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime, timezone
from typing import Iterable

from .utils import extract_domains, normalize_domain

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "xyz",
    "top",
    "click",
    "work",
    "support",
    "link",
    "cam",
    "stream",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
}

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_rfc1918_private(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in PRIVATE_NETS)


def is_non_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not ip.is_global


def is_ip_address(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def tld_of(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    return parts[-1] if parts else ""


def suspicious_tld(domain: str) -> bool:
    return tld_of(domain) in SUSPICIOUS_TLDS


def is_punycode(domain: str) -> bool:
    return "xn--" in domain


def is_url_shortener(domain: str) -> bool:
    return normalize_domain(domain) in URL_SHORTENERS


def count_subdomain_levels(domain: str) -> int:
    parts = normalize_domain(domain).split(".")
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def has_excessive_subdomains(domain: str, max_levels: int = 3) -> bool:
    return count_subdomain_levels(domain) > max_levels


def has_many_hyphens(domain: str, max_hyphens: int = 2) -> bool:
    return domain.count("-") > max_hyphens


def has_mixed_alnum(domain: str) -> bool:
    letters = any(ch.isalpha() for ch in domain)
    digits = any(ch.isdigit() for ch in domain)
    return letters and digits


def has_suspicious_port(port: str | None) -> bool:
    if not port:
        return False
    return port not in {"80", "443"}


def contains_encoded_chars(path: str) -> bool:
    return "%" in path


HOMOGLYPH_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
}


def normalize_homoglyphs(text: str) -> str:
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text.lower())


def homoglyph_severity(domain: str, legit: str) -> int:
    """Simple severity score based on substitutions and length."""
    domain_norm = normalize_domain(domain)
    legit_norm = normalize_domain(legit)
    if not domain_norm or not legit_norm:
        return 0
    substitutions = sum(
        1 for ch in domain_norm if ch in HOMOGLYPH_MAP
    )
    length_bonus = 2 if len(domain_norm) <= 10 else 0
    return min(10, substitutions * 2 + length_bonus)


def homoglyph_match(domain: str, legit_domains: Iterable[str]) -> list[dict]:
    """Detect simple homoglyph substitutions against legit domains."""
    matches: list[dict] = []
    domain_norm = normalize_domain(domain)
    domain_homoglyph = normalize_homoglyphs(domain_norm)
    for legit in legit_domains:
        legit_norm = normalize_domain(legit)
        legit_homoglyph = normalize_homoglyphs(legit_norm)
        if domain_norm == legit_norm:
            continue
        if domain_homoglyph == legit_homoglyph:
            matches.append({
                "domain": domain_norm,
                "legit": legit_norm,
                "normalized": domain_homoglyph,
                "severity": homoglyph_severity(domain_norm, legit_norm),
            })
    return matches


def levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein distance."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            insert = cur[j - 1] + 1
            delete = prev[j] + 1
            replace = prev[j - 1] + (ca != cb)
            cur.append(min(insert, delete, replace))
        prev = cur
    return prev[-1]


def check_lookalike(domain: str, legit_domains: Iterable[str], max_distance: int = 2) -> list[dict]:
    """Check domain against legit domains list for lookalikes."""
    findings: list[dict] = []
    norm = normalize_domain(domain)
    for legit in legit_domains:
        legit_norm = normalize_domain(legit)
        if norm == legit_norm:
            continue
        distance = levenshtein(norm, legit_norm)
        if distance <= max_distance:
            findings.append({
                "domain": norm,
                "legit": legit_norm,
                "distance": distance,
            })
    return findings


def parse_authentication_results(header_value: str | None) -> dict:
    """Parse Authentication-Results header for SPF/DKIM/DMARC."""
    if not header_value:
        return {
            "found": False,
            "spf": "not found",
            "dkim": "not found",
            "dmarc": "not found",
            "raw": "",
        }
    spf = re.search(r"spf=([a-zA-Z0-9_-]+)", header_value)
    dkim = re.search(r"dkim=([a-zA-Z0-9_-]+)", header_value)
    dmarc = re.search(r"dmarc=([a-zA-Z0-9_-]+)", header_value)
    return {
        "found": True,
        "spf": spf.group(1) if spf else "unknown",
        "dkim": dkim.group(1) if dkim else "unknown",
        "dmarc": dmarc.group(1) if dmarc else "unknown",
        "raw": header_value,
    }


def analyze_received_headers(received_headers: list[str]) -> dict:
    """Analyze Received headers for anomalies and hops."""
    hops: list[dict] = []
    anomalies: list[str] = []

    if not received_headers:
        anomalies.append("No Received headers found")
        return {"hops": hops, "anomalies": anomalies}

    for idx, header in enumerate(received_headers, start=1):
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", header)
        private_ips = [ip for ip in ips if is_rfc1918_private(ip)]
        non_public_ips = [ip for ip in ips if is_non_public_ip(ip) and ip not in private_ips]
        domains = extract_domains(header)
        suspicious_domains = [d for d in domains if suspicious_tld(d)]
        if private_ips:
            anomalies.append(f"Hop {idx}: private IP(s) {', '.join(private_ips)}")
        if non_public_ips:
            anomalies.append(f"Hop {idx}: non-public IP(s) {', '.join(non_public_ips)}")
        if suspicious_domains:
            anomalies.append(f"Hop {idx}: suspicious domain(s) {', '.join(suspicious_domains)}")
        hops.append({
            "index": idx,
            "raw": header,
            "ips": ips,
        })

    if len(hops) < 2:
        anomalies.append("Only one hop found in Received headers")

    return {"hops": hops, "anomalies": anomalies}


def display_name_mismatches(addresses: list[tuple[str, str]]) -> list[dict]:
    """Detect display-name vs email mismatches."""
    mismatches: list[dict] = []
    for display_name, email_addr in addresses:
        if not email_addr:
            continue
        if not display_name:
            continue
        display_lower = display_name.lower()
        local_part = email_addr.split("@")[0].lower()
        domain = email_addr.split("@")[-1].lower()
        if local_part not in display_lower and domain not in display_lower:
            mismatches.append({
                "display_name": display_name,
                "email": email_addr,
            })
    return mismatches


def domain_age_lookup(domain: str) -> dict | None:
    """Optional domain age lookup using python-whois if installed."""
    try:
        import whois  # type: ignore
    except Exception:
        return None

    try:
        result = whois.whois(domain)
        created = result.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return None
        if isinstance(created, datetime):
            created_dt = created
        else:
            return None
        now = datetime.now(timezone.utc)
        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=timezone.utc)
        age_days = (now - created_dt).days
        return {
            "domain": domain,
            "created": created_dt.isoformat(),
            "age_days": age_days,
        }
    except Exception:
        return None


def should_query_vt() -> bool:
    return bool(os.environ.get("VT_API_KEY"))
