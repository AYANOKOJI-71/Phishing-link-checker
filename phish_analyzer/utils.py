"""Utility helpers for phish-analyzer."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import string
from pathlib import Path
from typing import Iterable

SAFE_FILENAME_CHARS = f"{string.ascii_letters}{string.digits}._-"


def safe_filename(name: str, default: str = "attachment") -> str:
    """Return a filesystem-safe filename."""
    if not name:
        name = default
    cleaned = "".join(ch if ch in SAFE_FILENAME_CHARS else "_" for ch in name)
    cleaned = cleaned.strip("._")
    return cleaned or default


def sha256_bytes(data: bytes) -> str:
    """Compute SHA256 for bytes."""
    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()


def sha256_stream(chunks: Iterable[bytes]) -> str:
    """Compute SHA256 for a byte stream."""
    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(chunk)
    return digest.hexdigest()


def format_size(num_bytes: int) -> str:
    """Human-readable size."""
    for unit in ["B", "KB", "MB", "GB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.0f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.0f} TB"


def decode_html(text: str) -> str:
    """Decode HTML entities and strip nulls."""
    return html.unescape(text).replace("\x00", "")


def strip_surrounding_punct(url: str) -> str:
    """Strip common surrounding punctuation from a URL."""
    return url.strip("\"'<>[](){}.,;:!?")


def ensure_dir(path: str | Path) -> Path:
    """Create directory if missing."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_json(path: str | Path, data: dict) -> None:
    """Write JSON report to disk."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False)


def load_legit_domains(path: str | None) -> list[str]:
    """Load legit domains list from file, one per line."""
    if not path:
        return []
    domains: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            domains.append(line)
    return domains


def normalize_domain(domain: str) -> str:
    """Normalize domain string."""
    return domain.lower().strip().strip(".")


def extract_domains(text: str) -> list[str]:
    """Extract domain-like tokens from a string."""
    pattern = r"\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b"
    return re.findall(pattern, text)


def truncate(text: str, max_len: int = 200) -> str:
    """Truncate long text for terminal display."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def render_kv_lines(items: list[tuple[str, str]]) -> str:
    """Render a simple key-value section."""
    width = max((len(k) for k, _ in items), default=0)
    lines = [f"{k:<{width}} : {v}" for k, v in items]
    return "\n".join(lines)


def render_list(title: str, lines: list[str]) -> str:
    """Render a titled list section."""
    if not lines:
        lines = ["(none)"]
    block = "\n".join(f"- {line}" for line in lines)
    return f"{title}\n{block}"
