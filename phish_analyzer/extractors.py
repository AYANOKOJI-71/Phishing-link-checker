"""Extract URLs and attachments from email messages."""

from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import urlparse

from email.message import EmailMessage

from .indicators import (
    contains_encoded_chars,
    has_excessive_subdomains,
    has_many_hyphens,
    has_mixed_alnum,
    has_suspicious_port,
    homoglyph_match,
    is_ip_address,
    is_punycode,
    is_url_shortener,
    suspicious_tld,
)
from .utils import decode_html, safe_filename, sha256_bytes, strip_surrounding_punct

URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024


def iter_text_parts(message: EmailMessage) -> Iterable[str]:
    """Yield decoded text/plain and text/html parts."""
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            if content_type in {"text/plain", "text/html"}:
                try:
                    payload = part.get_content()
                except Exception:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload is None:
                            continue
                        charset = part.get_content_charset() or "utf-8"
                        payload = payload.decode(charset, errors="replace")
                    except Exception:
                        continue
                if content_type == "text/html":
                    payload = decode_html(str(payload))
                yield str(payload)
    else:
        try:
            payload = message.get_content()
        except Exception:
            payload = message.get_payload(decode=True)
            if payload is None:
                return
            charset = message.get_content_charset() or "utf-8"
            payload = payload.decode(charset, errors="replace")
        yield str(payload)


def extract_urls(
    message: EmailMessage,
    legit_domains: Iterable[str] | None = None,
    homoglyph_severity_min: int = 0,
) -> list[dict]:
    """Extract and analyze URLs from text parts."""
    found: dict[str, dict] = {}
    legit_list = list(legit_domains or [])
    for text in iter_text_parts(message):
        for raw_url in URL_PATTERN.findall(text):
            clean = strip_surrounding_punct(raw_url)
            if not clean:
                continue
            if clean in found:
                continue
            parsed = urlparse(clean)
            domain = parsed.netloc
            if "@" in domain:
                domain = domain.split("@")[-1]
            host, _, port = domain.partition(":")
            domain = host
            flags = []
            if is_ip_address(domain):
                flags.append("ip_in_url")
            if is_punycode(domain):
                flags.append("punycode")
            if suspicious_tld(domain):
                flags.append("suspicious_tld")
            if is_url_shortener(domain):
                flags.append("url_shortener")
            if has_excessive_subdomains(domain):
                flags.append("excessive_subdomains")
            if has_many_hyphens(domain):
                flags.append("many_hyphens")
            if has_mixed_alnum(domain):
                flags.append("mixed_alnum_domain")
            if has_suspicious_port(port):
                flags.append("suspicious_port")
            if contains_encoded_chars(parsed.path):
                flags.append("encoded_path")
            homoglyphs = homoglyph_match(domain, legit_list) if legit_list else []
            if homoglyphs and homoglyph_severity_min > 0:
                homoglyphs = [
                    h for h in homoglyphs if h.get("severity", 0) >= homoglyph_severity_min
                ]
            if homoglyphs:
                flags.append("homoglyph_domain")
            found[clean] = {
                "url": clean,
                "domain": domain,
                "scheme": parsed.scheme,
                "path": parsed.path or "/",
                "flags": flags,
                "homoglyph_matches": homoglyphs,
            }
    return list(found.values())


def extract_attachments(message: EmailMessage) -> list[dict]:
    """Extract attachment metadata and hashes."""
    attachments: list[dict] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        content_disposition = part.get_content_disposition()
        if content_disposition != "attachment" and not filename:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        size = len(payload)
        sha256 = None
        skipped_hash = False
        if size > MAX_ATTACHMENT_BYTES:
            skipped_hash = True
        else:
            sha256 = sha256_bytes(payload)
        attachments.append({
            "filename": filename or "(no filename)",
            "safe_filename": safe_filename(filename or "attachment"),
            "content_type": part.get_content_type(),
            "size": size,
            "sha256": sha256,
            "skipped_hash": skipped_hash,
            "_bytes": payload,
        })
    return attachments
