# Phishing Email Checker

A lightweight CLI tool that analyzes raw email files for common phishing signals (headers, links, language, and attachments).

**More cybersecurity tools at [Entry To Cyber](https://entrytocyber.com)**

---

## Features

- Parses `.eml` files or stdin input
- Flags Reply-To / Return-Path mismatches
- Checks SPF/DKIM/DMARC results when available
- Scans URLs for risky patterns (IP links, HTTP, punycode, high-risk TLDs)
- Detects common phishing language in the subject
- Highlights risky attachment types
- JSON output option for automation

## Installation

```bash
git clone https://github.com/soufnow/phishing-email-checker.git
cd phishing-email-checker
```

No dependencies required - Python 3.9+ only.

## Usage

### Basic Usage

```bash
# Analyze an .eml file
python phishing_email_checker.py suspicious.eml

# Analyze from stdin
cat suspicious.eml | python phishing_email_checker.py
```

### JSON Output

```bash
python phishing_email_checker.py suspicious.eml --json
```

## Example Output

```
======================================================
         PHISHING EMAIL CHECKER
======================================================
From:    "ACME Billing" <billing@acme-payments.example>
Subject: Urgent: Verify your account
Risk:    High (score: 7)
------------------------------------------------------
Findings:
  - Reply-To domain differs from From domain
  - SPF check is fail
  - URL uses plain HTTP
  - URL uses an IP address instead of a domain
  - Subject contains phishing-associated language
------------------------------------------------------
URLs:
  - http://198.51.100.42/verify
------------------------------------------------------
More tools: https://entrytocyber.com
======================================================
```

## Notes

- This tool is heuristic and does not guarantee a verdict.
- Always confirm with additional email security controls and user training.

## Related Tools

- [URL Encoder/Decoder](https://entrytocyber.com/url-encoder.html)
- [Port Scanner](https://entrytocyber.com/port-scanner.html)
- [Entry To Cyber](https://entrytocyber.com)

## Author

**Soufiane Taoufik**
Website: [entrytocyber.com](https://entrytocyber.com)

## License

MIT License
