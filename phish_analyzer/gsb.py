"""Google Safe Browsing (Lookup API v4 + hash lookup) integration (optional)."""

from __future__ import annotations

import os
import base64
import hashlib
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit


def _get_api_key() -> str | None:
    return os.environ.get("GSB_API_KEY")


def gsb_lookup_urls(
    urls: Iterable[str],
    client_id: str = "phish-analyzer",
    client_version: str = "0.1.0",
) -> dict[str, dict]:
    """Check URLs against Google Safe Browsing lists.

    Returns a dict keyed by URL with match details or empty matches.
    """
    api_key = _get_api_key()
    if not api_key:
        return {}

    try:
        import requests  # type: ignore
    except Exception:
        return {}

    url_list = [u for u in urls if u]
    if not url_list:
        return {}

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    params = {"key": api_key}
    body = {
        "client": {"clientId": client_id, "clientVersion": client_version},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in url_list],
        },
    }

    try:
        resp = requests.post(endpoint, params=params, json=body, timeout=10)
        if resp.status_code != 200:
            return {u: {"status": "error", "http_status": resp.status_code} for u in url_list}
        data = resp.json() or {}
    except Exception:
        return {u: {"status": "error"} for u in url_list}

    matches = data.get("matches", []) or []
    results: dict[str, dict] = {u: {"status": "clean", "matches": []} for u in url_list}
    for match in matches:
        threat = match.get("threat", {})
        threat_url = threat.get("url")
        if not threat_url:
            continue
        results.setdefault(threat_url, {"status": "matched", "matches": []})
        results[threat_url]["status"] = "matched"
        results[threat_url]["matches"].append({
            "threatType": match.get("threatType"),
            "platformType": match.get("platformType"),
            "threatEntryType": match.get("threatEntryType"),
            "cacheDuration": match.get("cacheDuration"),
        })

    return results


def _canonicalize_url(url: str) -> str:
    """Lightweight URL canonicalization for hashing."""
    url = url.strip()
    if not url:
        return url
    parts = urlsplit(url)
    scheme = parts.scheme.lower() or "http"
    netloc = parts.netloc.lower()
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def _hash_url_prefix(url: str, prefix_len: int = 4) -> bytes:
    digest = hashlib.sha256(url.encode("utf-8")).digest()
    return digest[:prefix_len]


def _hash_url_full(url: str) -> bytes:
    return hashlib.sha256(url.encode("utf-8")).digest()


def gsb_hash_check_urls(
    urls: Iterable[str],
    client_id: str = "phish-analyzer",
    client_version: str = "0.1.0",
) -> dict[str, dict]:
    """Check URLs via fullHashes.find using hash prefixes."""
    api_key = _get_api_key()
    if not api_key:
        return {}

    try:
        import requests  # type: ignore
    except Exception:
        return {}

    url_list = [u for u in urls if u]
    if not url_list:
        return {}

    canonical = [_canonicalize_url(u) for u in url_list]
    full_hashes = {_canonicalize_url(u): _hash_url_full(_canonicalize_url(u)) for u in url_list}
    prefixes = [_hash_url_prefix(u) for u in canonical]
    threat_entries = [{"hash": base64.b64encode(p).decode()} for p in prefixes]

    endpoint = "https://safebrowsing.googleapis.com/v4/fullHashes:find"
    params = {"key": api_key}
    body = {
        "client": {"clientId": client_id, "clientVersion": client_version},
        "clientStates": [],
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": threat_entries,
        },
    }

    results: dict[str, dict] = {u: {"status": "unknown", "matches": []} for u in url_list}

    try:
        resp = requests.post(endpoint, params=params, json=body, timeout=10)
        if resp.status_code != 200:
            return {u: {"status": "error", "http_status": resp.status_code} for u in url_list}
        data = resp.json() or {}
    except Exception:
        return {u: {"status": "error"} for u in url_list}

    matches = data.get("matches", []) or []
    if not matches:
        return {u: {"status": "clean", "matches": []} for u in url_list}

    for match in matches:
        threat = match.get("threat", {})
        match_hash_b64 = threat.get("hash")
        if not match_hash_b64:
            continue
        try:
            match_hash = base64.b64decode(match_hash_b64)
        except Exception:
            continue
        for original in url_list:
            canon = _canonicalize_url(original)
            if full_hashes.get(canon) == match_hash:
                results[original]["status"] = "matched"
                results[original]["matches"].append({
                    "threatType": match.get("threatType"),
                    "platformType": match.get("platformType"),
                    "threatEntryType": match.get("threatEntryType"),
                    "cacheDuration": match.get("cacheDuration"),
                })

    for url in url_list:
        if results[url]["status"] == "unknown":
            results[url]["status"] = "clean"

    return results
