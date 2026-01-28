#!/usr/bin/env python3
"""
Phishing Email Checker - heuristic CLI tool for flagging suspicious emails.

Author: Soufiane Taoufik
Website: https://entrytocyber.com
"""

import argparse
import email
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from ipaddress import ip_address
from urllib.parse import urlparse


URL_REGEX = re.compile(r"https?://[^\s)\]>\"']+", re.IGNORECASE)
HREF_REGEX = re.compile(r"href=[\"']([^\"']+)[\"']", re.IGNORECASE)
DOMAIN_LIKE_REGEX = re.compile(r"([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
AUTH_RESULTS_REGEX = re.compile(r"\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)")
SUSPICIOUS_WORDS = [
    "verify", "urgent", "suspend", "reset", "password", "invoice", "payment",
    "security", "alert", "login", "update", "confirm", "action required"
]
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "support"}


def read_email_bytes(path: str | None) -> bytes:
    if path:
        with open(path, "rb") as f:
            return f.read()
    return sys.stdin.buffer.read()


def extract_text_parts(msg: email.message.EmailMessage) -> str:
    texts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in {"text/plain", "text/html"}:
                try:
                    payload = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        payload = payload.decode(errors="ignore")
                if isinstance(payload, str):
                    texts.append(payload)
    else:
        try:
            payload = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode(errors="ignore")
        if isinstance(payload, str):
            texts.append(payload)
    return "\n".join(texts)


def extract_urls(text: str) -> list[str]:
    urls = set()
    for match in URL_REGEX.findall(text):
        urls.add(match.strip(".,;:!?)\"'"))
    for match in HREF_REGEX.findall(text):
        if match.lower().startswith("http"):
            urls.add(match.strip(".,;:!?)\"'"))
    return sorted(urls)


def domain_from_email(addr: str) -> str:
    _, email_addr = parseaddr(addr)
    if "@" in email_addr:
        return email_addr.split("@", 1)[1].lower()
    return ""


def domain_from_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.netloc
        if "@" in host:
            host = host.split("@", 1)[1]
        host = host.split(":", 1)[0].lower()
        return host
    except Exception:
        return ""


def is_ip(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except Exception:
        return False


def find_auth_results(headers: list[str]) -> dict[str, str]:
    results: dict[str, str] = {}
    for header in headers:
        for key, value in AUTH_RESULTS_REGEX.findall(header):
            results[key] = value
    return results


def analyze_email(msg: email.message.EmailMessage) -> dict:
    findings = []
    score = 0

    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    subject = msg.get("Subject", "")
    auth_results_headers = msg.get_all("Authentication-Results", []) or []

    from_domain = domain_from_email(from_header)
    reply_domain = domain_from_email(reply_to)
    return_domain = domain_from_email(return_path)

    display_name, _ = parseaddr(from_header)
    display_domain_match = DOMAIN_LIKE_REGEX.search(display_name or "")
    if display_domain_match:
        display_domain = display_domain_match.group(1).lower()
        if from_domain and display_domain not in from_domain:
            findings.append("Display name contains a domain that differs from From domain")
            score += 1

    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append("Reply-To domain differs from From domain")
        score += 2

    if return_domain and from_domain and return_domain != from_domain:
        findings.append("Return-Path domain differs from From domain")
        score += 1

    auth_results = find_auth_results(auth_results_headers)
    if auth_results:
        for key in ["spf", "dkim", "dmarc"]:
            result = auth_results.get(key)
            if result in {"fail", "softfail", "neutral", "none", "temperror", "permerror"}:
                findings.append(f"{key.upper()} check is {result}")
                score += 2
    else:
        findings.append("No Authentication-Results header found")
        score += 1

    body_text = extract_text_parts(msg)
    urls = extract_urls(body_text)

    if urls:
        for url in urls:
            host = domain_from_url(url)
            if not host:
                continue
            if host.startswith("xn--"):
                findings.append("Punycode domain detected")
                score += 2
            if is_ip(host):
                findings.append("URL uses an IP address instead of a domain")
                score += 2
            if url.lower().startswith("http://"):
                findings.append("URL uses plain HTTP")
                score += 1
            tld = host.rsplit(".", 1)[-1]
            if tld in SUSPICIOUS_TLDS:
                findings.append("URL uses a higher-risk TLD")
                score += 1

    if subject:
        lowered = subject.lower()
        for word in SUSPICIOUS_WORDS:
            if word in lowered:
                findings.append("Subject contains phishing-associated language")
                score += 1
                break

    attachment_exts = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".lnk", ".iso"}
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            lower = filename.lower()
            if any(lower.endswith(ext) for ext in attachment_exts):
                findings.append("Executable or script attachment detected")
                score += 3
                break

    risk = "Low"
    if score >= 6:
        risk = "High"
    elif score >= 3:
        risk = "Medium"

    return {
        "from": from_header,
        "subject": subject,
        "from_domain": from_domain,
        "reply_to": reply_to,
        "risk": risk,
        "score": score,
        "findings": findings,
        "urls": urls,
    }


def format_report(report: dict) -> str:
    lines = []
    lines.append("=" * 54)
    lines.append("         PHISHING EMAIL CHECKER")
    lines.append("=" * 54)
    lines.append(f"From:    {report['from']}")
    lines.append(f"Subject: {report['subject']}")
    lines.append(f"Risk:    {report['risk']} (score: {report['score']})")
    lines.append("-" * 54)

    if report["findings"]:
        lines.append("Findings:")
        for item in report["findings"]:
            lines.append(f"  - {item}")
    else:
        lines.append("Findings: none detected")

    if report["urls"]:
        lines.append("-" * 54)
        lines.append("URLs:")
        for url in report["urls"]:
            lines.append(f"  - {url}")

    lines.append("-" * 54)
    lines.append("More tools: https://entrytocyber.com")
    lines.append("=" * 54)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phishing Email Checker (heuristic)",
        epilog="More tools at: https://entrytocyber.com"
    )
    parser.add_argument("file", nargs="?", help="Path to .eml file (or read from stdin)")
    parser.add_argument("-j", "--json", action="store_true", help="Output JSON report")

    args = parser.parse_args()

    raw = read_email_bytes(args.file)
    if not raw:
        print("Error: no email content provided", file=sys.stderr)
        sys.exit(1)

    msg = BytesParser(policy=policy.default).parsebytes(raw)
    report = analyze_email(msg)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(format_report(report))


if __name__ == "__main__":
    main()
