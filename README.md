# 🛡️ CORS & Security Header Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-OWASP-FF6F00?style=for-the-badge&logo=owasp&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge)

**A lightweight Python tool that audits HTTP response headers against OWASP best practices, identifies CORS misconfigurations, and flags information-disclosure risks — with color-coded terminal output.**

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [Usage](#-usage)
- [Headers Checked](#-headers-checked)
- [Understanding the Output](#-understanding-the-output)
- [OWASP References](#-owasp-references)
- [Disclaimer](#%EF%B8%8F-disclaimer)
- [License](#-license)

---

## 🔍 Overview

Misconfigured HTTP security headers are one of the most common — and preventable — web application vulnerabilities. Missing headers like `Strict-Transport-Security`, `Content-Security-Policy`, or a wildcard `Access-Control-Allow-Origin` can expose applications to clickjacking, XSS, MIME-sniffing, and cross-origin data theft.

**CORS & Security Header Scanner** automates the audit process by:

1. Fetching response headers from a target URL
2. Evaluating each security-critical header against OWASP recommended configurations
3. Detecting permissive CORS policies (wildcard `*`, `null` origins, credential leaks)
4. Flagging information-disclosure headers (`X-Powered-By`, `Server`)
5. Presenting findings with **color-coded severity** in the terminal

---

## ✨ Features

| Feature | Description |
|---|---|
| **OWASP-Based Checks** | 9 critical security headers validated against OWASP Secure Headers Project |
| **CORS Analysis** | Detects wildcard origins, `null` origin abuse, and credential misconfigurations |
| **Information Disclosure** | Flags `X-Powered-By`, `Server`, and `X-AspNet-Version` headers |
| **Value Validation** | Goes beyond presence checks — validates HSTS `max-age`, CSP directives, etc. |
| **Color-Coded Output** | 🟢 Green (secure), 🔴 Red (vulnerable/missing), 🟡 Yellow (warning) |
| **JSON Export** | Export full scan results to JSON for integration or reporting |
| **Timeout Handling** | Graceful error handling for unreachable targets and network timeouts |
| **SSL Flexibility** | Optional `--no-verify` flag for testing self-signed certificates |
| **Zero Config** | Single dependency (`requests`), runs immediately |

---

## ⚙️ How It Works

```
┌─────────────────────────────────────────────────────────┐
│                  Target URL (input)                     │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │   HTTP GET Request   │
            │  (fetch headers)     │
            └──────────┬───────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
   ┌────────────┐ ┌─────────┐ ┌───────────────┐
   │   CORS     │ │Security │ │  Information   │
   │  Analysis  │ │ Headers │ │  Disclosure    │
   └─────┬──────┘ └────┬────┘ └──────┬────────┘
         │             │             │
         └─────────────┼─────────────┘
                       ▼
            ┌──────────────────────┐
            │  Color-Coded Report  │
            │  + Optional JSON     │
            └──────────────────────┘
```

---

## 🚀 Installation

### Prerequisites

- Python 3.10 or higher
- `pip` package manager

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/CORS-Header-Scanner.git
cd CORS-Header-Scanner

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

### Basic Scan

```bash
python cors_header_scanner.py https://example.com
```

### With Custom Timeout

```bash
python cors_header_scanner.py https://example.com --timeout 15
```

### Export Results to JSON

```bash
python cors_header_scanner.py https://example.com --json report.json
```

### Skip SSL Verification (self-signed certs)

```bash
python cors_header_scanner.py https://internal-server.local --no-verify
```

### Full Options

```
usage: cors_header_scanner.py [-h] [--timeout TIMEOUT] [--json FILE] [--no-verify] url

positional arguments:
  url               Target URL to scan (include https://)

options:
  -h, --help        show this help message and exit
  --timeout TIMEOUT  Request timeout in seconds (default: 10)
  --json FILE       Export results to a JSON file
  --no-verify       Disable SSL certificate verification
```

---

## 🔐 Headers Checked

### Security Headers (OWASP Baseline)

| Header | Severity | Purpose |
|---|---|---|
| `Strict-Transport-Security` | 🔴 HIGH | Enforces HTTPS via HSTS; checks `max-age ≥ 1 year` and `includeSubDomains` |
| `X-Frame-Options` | 🔴 HIGH | Prevents clickjacking; validates `DENY` or `SAMEORIGIN` |
| `Content-Security-Policy` | 🔴 HIGH | Mitigates XSS; flags `unsafe-inline` and `unsafe-eval` |
| `X-Content-Type-Options` | 🟡 MEDIUM | Prevents MIME sniffing; validates `nosniff` |
| `Permissions-Policy` | 🟡 MEDIUM | Restricts browser APIs (camera, mic, geolocation) |
| `Cross-Origin-Opener-Policy` | 🟡 MEDIUM | Isolates browsing context from cross-origin windows |
| `Cross-Origin-Resource-Policy` | 🟡 MEDIUM | Controls cross-origin resource loading |
| `Referrer-Policy` | 🟢 LOW | Controls referrer information leakage |
| `X-Permitted-Cross-Domain-Policies` | 🟢 LOW | Controls Flash/PDF cross-domain access |

### CORS Configuration

| Check | Severity | Description |
|---|---|---|
| Wildcard `*` origin | 🔴 HIGH | Any origin can read responses |
| `null` origin | 🔴 HIGH | Exploitable via sandboxed iframes |
| Credentials + wildcard | 🔴 HIGH | Dangerous combination indicating misconfiguration |
| Credentials + reflected origin | 🟡 MEDIUM | Requires strict server-side validation |

### Information Disclosure

| Header | Severity | Risk |
|---|---|---|
| `X-Powered-By` | 🟡 MEDIUM | Reveals backend technology stack |
| `Server` | 🟢 LOW | Exposes web server software/version |
| `X-AspNet-Version` | 🟡 MEDIUM | Discloses ASP.NET framework version |

---

## 📊 Understanding the Output

The scanner uses four status indicators:

| Icon | Status | Meaning |
|---|---|---|
| 🟢 `✔ SECURE` | PASS | Header is present and correctly configured |
| 🔴 `✘ VULNERABLE` | FAIL | Header is missing or dangerously misconfigured |
| 🟡 `⚠ WARNING` | WARN | Header is present but has a weak configuration |
| 🔵 `ℹ INFO` | INFO | Informational finding, no action required |

### Security Score

A percentage score is calculated based on passed checks:

- **≥ 80%** — Good security posture (green)
- **50–79%** — Needs improvement (yellow)
- **< 50%** — Critical gaps in header security (red)

---

## 📚 OWASP References

This tool's checks are aligned with:

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP HTTP Strict Transport Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [OWASP Testing Guide — CORS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [MDN Web Docs — HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

---

## ⚠️ Disclaimer

> **This tool is intended for authorized security testing and educational purposes only.**
>
> Always obtain explicit written permission before scanning any system you do not own. Unauthorized scanning may violate applicable laws and regulations. The authors assume no liability for misuse of this tool.

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for defenders. Inspired by OWASP.**

</div>
