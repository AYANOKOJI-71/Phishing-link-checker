"""Email parsing and report building."""

from __future__ import annotations

import os
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from typing import Iterable

from .extractors import extract_attachments, extract_urls
from .gsb import gsb_hash_check_urls, gsb_lookup_urls
from .indicators import (
    analyze_received_headers,
    check_lookalike,
    display_name_mismatches,
    domain_age_lookup,
    parse_authentication_results,
    should_query_vt,
)
from .utils import ensure_dir, load_legit_domains, normalize_domain, write_json
from .vt import vt_lookup_hash, vt_lookup_url


def parse_eml(path: str) -> EmailMessage:
    """Parse .eml file using Python's email package."""
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def extract_addresses(message: EmailMessage, headers: Iterable[str]) -> list[tuple[str, str]]:
    values = []
    for header in headers:
        values.extend(getaddresses(message.get_all(header, [])))
    return values


def build_report(
    eml_path: str,
    out_dir: str,
    legit_domains_path: str | None = None,
    save_attachments_dir: str | None = None,
    yara_rules_dir: str | None = None,
    homoglyph_severity_min: int = 0,
    use_gsb_hash: bool = False,
) -> dict:
    """Build a structured report for a phishing analysis."""
    errors: list[str] = []
    message = parse_eml(eml_path)

    headers = {
        "from": message.get("From", ""),
        "reply_to": message.get("Reply-To", ""),
        "return_path": message.get("Return-Path", ""),
        "subject": message.get("Subject", ""),
        "date": message.get("Date", ""),
        "message_id": message.get("Message-ID", ""),
    }

    received_headers = message.get_all("Received", [])
    received_analysis = analyze_received_headers(received_headers)

    address_list = extract_addresses(message, ["From", "Reply-To", "Return-Path"])
    mismatches = display_name_mismatches(address_list)

    legit_domains = load_legit_domains(legit_domains_path)
    lookalike_findings: list[dict] = []
    for _, email_addr in address_list:
        if "@" not in email_addr:
            continue
        domain = normalize_domain(email_addr.split("@")[-1])
        lookalike_findings.extend(check_lookalike(domain, legit_domains))

    auth_results = parse_authentication_results(message.get("Authentication-Results"))

    urls = extract_urls(
        message,
        legit_domains=legit_domains,
        homoglyph_severity_min=homoglyph_severity_min,
    )
    gsb_urls = [u.get("url", "") for u in urls]
    if use_gsb_hash:
        gsb_results = gsb_hash_check_urls(gsb_urls)
        if gsb_results:
            for url in urls:
                result = gsb_results.get(url.get("url", ""), {})
                if result:
                    url["gsb_hash"] = result
    else:
        gsb_results = gsb_lookup_urls(gsb_urls)
        if gsb_results:
            for url in urls:
                result = gsb_results.get(url.get("url", ""), {})
                if result:
                    url["gsb"] = result
    for url in urls:
        domain_age = domain_age_lookup(url["domain"])
        if domain_age:
            url["domain_age"] = domain_age
        if should_query_vt() and url.get("url"):
            url["vt"] = vt_lookup_url(url["url"]) or {}

    attachments = extract_attachments(message)

    if yara_rules_dir:
        try:
            import yara  # type: ignore
        except Exception:
            errors.append("YARA rules provided but yara-python not installed")
        else:
            rules = yara.compile(filepath=os.path.join(yara_rules_dir, "rules.yar"))
            for attachment in attachments:
                try:
                    matches = rules.match(data=attachment.get("_bytes", b""))
                    attachment["yara_matches"] = [m.rule for m in matches]
                except Exception:
                    attachment["yara_matches"] = []

    if should_query_vt():
        for attachment in attachments:
            if attachment.get("sha256"):
                attachment["vt"] = vt_lookup_hash(attachment["sha256"]) or {}

    saved_files = []
    if save_attachments_dir:
        out_path = ensure_dir(save_attachments_dir)
        for attachment in attachments:
            data = attachment.get("_bytes", b"")
            safe_name = attachment.get("safe_filename", "attachment")
            dest = out_path / safe_name
            try:
                with open(dest, "wb") as f:
                    f.write(data)
                attachment["saved_to"] = str(dest)
                saved_files.append(str(dest))
            except Exception as exc:
                errors.append(f"Failed to save attachment {safe_name}: {exc}")

    for attachment in attachments:
        attachment.pop("_bytes", None)

    risk_score = 0
    risk_reasons: list[str] = []

    if auth_results.get("found"):
        if auth_results.get("spf") not in {"pass", "none"}:
            risk_score += 3
            risk_reasons.append(f"SPF result: {auth_results.get('spf')}")
        if auth_results.get("dkim") not in {"pass", "none"}:
            risk_score += 3
            risk_reasons.append(f"DKIM result: {auth_results.get('dkim')}")
        if auth_results.get("dmarc") not in {"pass", "none"}:
            risk_score += 3
            risk_reasons.append(f"DMARC result: {auth_results.get('dmarc')}")
    else:
        risk_score += 1
        risk_reasons.append("Authentication-Results header not found")

    if mismatches:
        risk_score += min(3, len(mismatches))
        risk_reasons.append("Display name mismatch detected")

    if received_analysis.get("anomalies"):
        risk_score += min(3, len(received_analysis["anomalies"]))
        risk_reasons.append("Received header anomalies detected")

    flag_weights = {
        "ip_in_url": 4,
        "punycode": 3,
        "suspicious_tld": 3,
        "url_shortener": 2,
        "excessive_subdomains": 1,
        "many_hyphens": 1,
        "mixed_alnum_domain": 1,
        "suspicious_port": 2,
        "encoded_path": 1,
        "homoglyph_domain": 4,
    }
    for url in urls:
        flags = url.get("flags", [])
        for flag in flags:
            risk_score += flag_weights.get(flag, 0)
            if flag not in risk_reasons:
                risk_reasons.append(f"URL flag: {flag}")
        gsb = url.get("gsb_hash") or url.get("gsb", {})
        if gsb.get("status") == "matched":
            risk_score += 6
            risk_reasons.append("Google Safe Browsing match")
        elif gsb.get("status") == "error":
            risk_reasons.append("Google Safe Browsing lookup error")

    if risk_score <= 2:
        risk_level = "low"
        risk_message = "The possibility of the link being phishing is low."
    elif risk_score <= 5:
        risk_level = "medium"
        risk_message = "The possibility of the link being phishing is medium."
    else:
        risk_level = "high"
        risk_message = "The possibility of the link being phishing is high."

    report = {
        "input_file": eml_path,
        "headers": headers,
        "received": received_analysis,
        "display_name_mismatch": mismatches,
        "lookalike_domains": lookalike_findings,
        "auth_results": auth_results,
        "urls": urls,
        "attachments": attachments,
        "saved_attachments": saved_files,
        "risk_assessment": {
            "score": risk_score,
            "level": risk_level,
            "message": risk_message,
            "reasons": risk_reasons,
        },
        "errors": errors,
    }

    out_path = ensure_dir(out_dir)
    json_path = out_path / (Path(eml_path).name + ".json")
    write_json(json_path, report)
    report["json_path"] = str(json_path)
    return report
