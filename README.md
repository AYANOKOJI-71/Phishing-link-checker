# phish-analyzer

phish-analyzer is a small command-line tool that reads an email file (`.eml`) and gives you a clean report. It pulls out headers, links, and attachments, then highlights anything that looks risky. It saves both a readable report and a JSON file.

Description: A simple phishing email analyzer for `.eml` files with URL, header, and attachment checks.

## What it does
- Reads `.eml` files using Python’s built-in `email` package.
- Shows important headers like From, Reply-To, Subject, and Message-ID.
- Lists the email’s Received hops and flags odd ones.
- Finds links in text and HTML and marks risky patterns.
- Lists attachments and computes SHA256 hashes.
- Optional add-ons for VirusTotal, Google Safe Browsing, WHOIS, and YARA.

## Install

1. Create and activate a virtual environment.
2. Install the optional dependencies if you want extra checks.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run it

```bash
python -m phish_analyzer.cli analyze path/to/email.eml --out reports/
python -m phish_analyzer.cli analyze path/to/email.eml --out reports/ --save-attachments attachments/
python -m phish_analyzer.cli analyze path/to/email.eml --out reports/ --legit-domains legit.txt --yara-rules yara_rules/
python -m phish_analyzer.cli analyze path/to/email.eml --out reports/ --legit-domains legit.txt --homoglyph-severity-min 4
python -m phish_analyzer.cli analyze path/to/email.eml --out reports/ --gsb-hash-check
python -m phish_analyzer.cli gsb-check https://example.com/
```

Short runner from the repo root:

```bash
./run.sh analyze path/to/email.eml --out reports/
```

## Test

```bash
./test.sh
```

## Sample output

```
Headers
From        : "Example Support" <support@example.com>
Reply-To    : "Example Support" <support@example.com>
Return-Path : <bounce@example.com>
Subject     : Account Notice (Benign)
Date        : Tue, 03 Feb 2026 10:15:00 -0000
Message-ID  : <benign-001@example.com>

Received Hops
- Hop 1: from mail.example.com (192.0.2.10) by mx.example.com with ESMTP; Tue, 03 Feb 2026 10:15:00 -0000

Received Anomalies
- (none)

Authentication Results
SPF  : pass
DKIM : pass
DMARC: pass

Display Name Mismatches
- (none)

Lookalike Domains
- (none)

URLs
- https://example.com/help | domain=example.com | flags=none

Attachments
- (none)

JSON report saved to: reports/benign_notice.eml.json
```

## Security notes
- Do not open unknown attachments on your main machine.
- Use a sandbox if you need to inspect suspicious files.
- This tool does not make network calls unless you enable optional integrations.

## Optional integrations
- VirusTotal: set `VT_API_KEY` to check URL and file reputation.
- Google Safe Browsing: set `GSB_API_KEY` to check URLs.
- WHOIS: install `python-whois` to get domain age.
- YARA: install `yara-python` and provide a rules directory with `rules.yar`.
# AYANOKOJI-71
