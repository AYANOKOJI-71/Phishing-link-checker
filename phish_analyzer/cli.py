"""Command-line interface for phish-analyzer."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from .parser import build_report
from .utils import format_size, render_kv_lines, render_list, truncate
from .gsb import gsb_hash_check_urls


def _format_received(report: dict) -> str:
    hops = report.get("received", {}).get("hops", [])
    anomalies = report.get("received", {}).get("anomalies", [])
    hop_lines = []
    for hop in hops:
        raw = truncate(hop.get("raw", ""), 140)
        hop_lines.append(f"Hop {hop.get('index')}: {raw}")
    return "\n".join([
        render_list("Received Hops", hop_lines),
        render_list("Received Anomalies", anomalies),
    ])


def _format_urls(report: dict) -> str:
    urls = report.get("urls", [])
    lines = []
    for url in urls:
        flags = ", ".join(url.get("flags", [])) or "none"
        line = f"{url.get('url')} | domain={url.get('domain')} | flags={flags}"
        lines.append(line)
    return render_list("URLs", lines)


def _format_attachments(report: dict) -> str:
    attachments = report.get("attachments", [])
    lines = []
    for att in attachments:
        sha = att.get("sha256")
        sha_display = sha[:12] + "..." if sha else "(not hashed)"
        size = format_size(att.get("size", 0))
        saved_to = att.get("saved_to")
        extra = f" saved_to={saved_to}" if saved_to else ""
        lines.append(
            f"{att.get('filename')} | {att.get('content_type')} | {size} | sha256={sha_display}{extra}"
        )
    return render_list("Attachments", lines)


def _format_display_mismatches(report: dict) -> str:
    mismatches = report.get("display_name_mismatch", [])
    lines = [f"{m['display_name']} <{m['email']}>" for m in mismatches]
    return render_list("Display Name Mismatches", lines)


def _format_lookalikes(report: dict) -> str:
    findings = report.get("lookalike_domains", [])
    lines = [f"{f['domain']} ~ {f['legit']} (distance {f['distance']})" for f in findings]
    return render_list("Lookalike Domains", lines)


def _format_auth(report: dict) -> str:
    auth = report.get("auth_results", {})
    items = [
        ("SPF", auth.get("spf", "")),
        ("DKIM", auth.get("dkim", "")),
        ("DMARC", auth.get("dmarc", "")),
    ]
    return "Authentication Results\n" + render_kv_lines(items)


def _format_headers(report: dict) -> str:
    headers = report.get("headers", {})
    items = [
        ("From", headers.get("from", "")),
        ("Reply-To", headers.get("reply_to", "")),
        ("Return-Path", headers.get("return_path", "")),
        ("Subject", headers.get("subject", "")),
        ("Date", headers.get("date", "")),
        ("Message-ID", headers.get("message_id", "")),
    ]
    return "Headers\n" + render_kv_lines(items)


def _format_risk(report: dict) -> str:
    risk = report.get("risk_assessment", {})
    items = [
        ("Level", risk.get("level", "")),
        ("Score", str(risk.get("score", ""))),
        ("Message", risk.get("message", "")),
    ]
    block = render_kv_lines(items)
    reasons = risk.get("reasons", [])
    return "\n".join(["Risk Assessment", block, render_list("Reasons", reasons)])


def format_report_text(report: dict) -> str:
    sections = [
        _format_headers(report),
        _format_received(report),
        _format_auth(report),
        _format_risk(report),
        _format_display_mismatches(report),
        _format_lookalikes(report),
        _format_urls(report),
        _format_attachments(report),
    ]
    errors = report.get("errors", [])
    if errors:
        sections.append(render_list("Errors", errors))
    sections.append(f"JSON report saved to: {report.get('json_path')}")
    return "\n\n".join(sections)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phish-analyzer", description="Analyze phishing .eml files")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze a .eml file")
    analyze.add_argument("eml_path", help="Path to .eml file")
    analyze.add_argument("--out", required=True, help="Output directory for reports")
    analyze.add_argument("--save-attachments", help="Directory to save attachments")
    analyze.add_argument("--legit-domains", help="Path to legit domains list")
    analyze.add_argument("--yara-rules", help="Directory containing YARA rules")
    analyze.add_argument(
        "--homoglyph-severity-min",
        type=int,
        default=0,
        help="Minimum homoglyph severity to report (0-10)",
    )
    analyze.add_argument(
        "--gsb-hash-check",
        action="store_true",
        help="Use Google Safe Browsing hash lookup (fullHashes:find) instead of lookup API",
    )

    gsb = subparsers.add_parser("gsb-check", help="Check a URL with Google Safe Browsing")
    gsb.add_argument("url", help="URL to check")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        report = build_report(
            eml_path=args.eml_path,
            out_dir=args.out,
            legit_domains_path=args.legit_domains,
            save_attachments_dir=args.save_attachments,
            yara_rules_dir=args.yara_rules,
            homoglyph_severity_min=args.homoglyph_severity_min,
            use_gsb_hash=args.gsb_hash_check,
        )
        print(format_report_text(report))
        return 0
    if args.command == "gsb-check":
        results = gsb_hash_check_urls([args.url])
        if not results:
            print("GSB API key missing or request failed.")
            return 1
        result = results.get(args.url, {})
        print(render_list("GSB Check", [f"{args.url} -> {result.get('status', 'unknown')}"]))
        matches = result.get("matches", [])
        if matches:
            print(render_list("Matches", [str(m) for m in matches]))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
