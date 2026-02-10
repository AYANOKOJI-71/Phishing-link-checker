"""VirusTotal integration (optional)."""

from __future__ import annotations

import os
from typing import Any

VT_API_BASE = "https://www.virustotal.com/api/v3"


def _headers() -> dict:
    return {"x-apikey": os.environ.get("VT_API_KEY", "")}


def _request(path: str) -> dict | None:
    try:
        import requests  # type: ignore
    except Exception:
        return None

    url = f"{VT_API_BASE}{path}"
    try:
        resp = requests.get(url, headers=_headers(), timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def vt_lookup_url(url: str) -> dict | None:
    """Query VT for a URL."""
    try:
        import base64

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    except Exception:
        return None
    data = _request(f"/urls/{url_id}")
    return _summarize(data)


def vt_lookup_hash(sha256: str) -> dict | None:
    """Query VT for a file hash."""
    data = _request(f"/files/{sha256}")
    return _summarize(data)


def _summarize(data: dict | None) -> dict | None:
    if not data:
        return None
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats")
    if not stats:
        return None
    return {
        "last_analysis_stats": stats,
    }
