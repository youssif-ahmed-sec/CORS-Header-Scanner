#!/usr/bin/env python3
"""
CORS & Security Header Scanner
───────────────────────────────
Audits HTTP response headers against OWASP best practices.
Checks for missing, misconfigured, or overly-permissive headers
including HSTS, X-Frame-Options, Content-Security-Policy, and
Access-Control-Allow-Origin (CORS).

Author  : Security Automation
License : MIT
"""

import argparse
import sys
import json
import textwrap
from datetime import datetime, timezone

try:
    import requests
    from requests.exceptions import Timeout, ConnectionError, RequestException
except ImportError:
    print("[!] The 'requests' library is required. Install it with:")
    print("    pip install requests")
    sys.exit(1)


# ──────────────────────────────────────────────
# ANSI colour helpers
# ──────────────────────────────────────────────
class Color:
    """ANSI escape codes for terminal colours."""
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

    @staticmethod
    def green(text: str) -> str:
        return f"{Color.GREEN}{text}{Color.RESET}"

    @staticmethod
    def red(text: str) -> str:
        return f"{Color.RED}{text}{Color.RESET}"

    @staticmethod
    def yellow(text: str) -> str:
        return f"{Color.YELLOW}{text}{Color.RESET}"

    @staticmethod
    def cyan(text: str) -> str:
        return f"{Color.CYAN}{text}{Color.RESET}"

    @staticmethod
    def bold(text: str) -> str:
        return f"{Color.BOLD}{text}{Color.RESET}"

    @staticmethod
    def dim(text: str) -> str:
        return f"{Color.DIM}{text}{Color.RESET}"


# ──────────────────────────────────────────────
# Security header definitions (OWASP baseline)
# ──────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections via HSTS policy.",
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        "severity": "HIGH",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "reference": "https://owasp.org/www-project-secure-headers/#x-frame-options",
        "severity": "HIGH",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing attacks.",
        "reference": "https://owasp.org/www-project-secure-headers/#x-content-type-options",
        "severity": "MEDIUM",
        "recommendation": "Add 'X-Content-Type-Options: nosniff'",
    },
    "Content-Security-Policy": {
        "description": "Mitigates XSS and data injection attacks via CSP directives.",
        "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        "severity": "HIGH",
        "recommendation": "Define a strict Content-Security-Policy tailored to your application.",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is sent with requests.",
        "reference": "https://owasp.org/www-project-secure-headers/#referrer-policy",
        "severity": "LOW",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'",
    },
    "Permissions-Policy": {
        "description": "Restricts browser features (camera, microphone, geolocation, etc.).",
        "reference": "https://owasp.org/www-project-secure-headers/#permissions-policy",
        "severity": "MEDIUM",
        "recommendation": "Add 'Permissions-Policy' to disable unnecessary browser features.",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "Controls cross-domain data loading for Flash/PDF plugins.",
        "reference": "https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies",
        "severity": "LOW",
        "recommendation": "Add 'X-Permitted-Cross-Domain-Policies: none'",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing context to prevent cross-origin attacks.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
        "severity": "MEDIUM",
        "recommendation": "Add 'Cross-Origin-Opener-Policy: same-origin'",
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Prevents resources from being loaded by other origins.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
        "severity": "MEDIUM",
        "recommendation": "Add 'Cross-Origin-Resource-Policy: same-origin'",
    },
}

# Headers that should NOT be present (information disclosure)
DEPRECATED_HEADERS = {
    "X-Powered-By": {
        "description": "Reveals backend technology — aids attacker reconnaissance.",
        "severity": "MEDIUM",
        "recommendation": "Remove the 'X-Powered-By' header from server responses.",
    },
    "Server": {
        "description": "Exposes web server software and version information.",
        "severity": "LOW",
        "recommendation": "Suppress or genericise the 'Server' header.",
    },
    "X-AspNet-Version": {
        "description": "Discloses ASP.NET framework version.",
        "severity": "MEDIUM",
        "recommendation": "Remove the 'X-AspNet-Version' header.",
    },
}


# ──────────────────────────────────────────────
# Core scanning logic
# ──────────────────────────────────────────────
def fetch_headers(url: str, timeout: int = 10, verify_ssl: bool = True) -> dict:
    """Send a GET request and return response headers + metadata."""
    headers = {
        "User-Agent": "CORS-Header-Scanner/1.0 (Security Audit Tool)"
    }
    response = requests.get(url, headers=headers, timeout=timeout,
                            verify=verify_ssl, allow_redirects=True)
    return {
        "status_code": response.status_code,
        "url": response.url,
        "headers": dict(response.headers),
        "elapsed": response.elapsed.total_seconds(),
    }


def analyse_cors(headers: dict) -> list:
    """Check Access-Control-Allow-Origin for permissive CORS misconfigs."""
    findings = []
    acao = headers.get("Access-Control-Allow-Origin")
    acac = headers.get("Access-Control-Allow-Credentials")

    if acao is None:
        findings.append({
            "header": "Access-Control-Allow-Origin",
            "status": "INFO",
            "value": "Not present",
            "detail": "No CORS header detected. This is acceptable if cross-origin "
                      "access is not required.",
        })
        return findings

    # Wildcard origin
    if acao.strip() == "*":
        findings.append({
            "header": "Access-Control-Allow-Origin",
            "status": "FAIL",
            "value": acao,
            "detail": "Wildcard '*' allows ANY origin to read responses. "
                      "This is a permissive CORS misconfiguration.",
            "severity": "HIGH",
            "recommendation": "Restrict Access-Control-Allow-Origin to specific trusted origins.",
        })
    # Null origin (can be spoofed via sandboxed iframes)
    elif acao.strip().lower() == "null":
        findings.append({
            "header": "Access-Control-Allow-Origin",
            "status": "FAIL",
            "value": acao,
            "detail": "The 'null' origin is exploitable via sandboxed iframes "
                      "and should never be trusted.",
            "severity": "HIGH",
            "recommendation": "Never whitelist 'null' as a trusted origin.",
        })
    else:
        findings.append({
            "header": "Access-Control-Allow-Origin",
            "status": "PASS",
            "value": acao,
            "detail": f"CORS restricted to specific origin: {acao}",
        })

    # Dangerous combo: credentials + wildcard
    if acac and acac.strip().lower() == "true":
        if acao and acao.strip() == "*":
            findings.append({
                "header": "Access-Control-Allow-Credentials",
                "status": "FAIL",
                "value": acac,
                "detail": "Credentials flag is 'true' while origin is '*'. "
                          "Browsers block this, but the intent signals misconfiguration.",
                "severity": "HIGH",
                "recommendation": "Do not combine wildcard origin with credentials.",
            })
        else:
            findings.append({
                "header": "Access-Control-Allow-Credentials",
                "status": "WARN",
                "value": acac,
                "detail": "Credentials are allowed for cross-origin requests. "
                          "Ensure the reflected origin is strictly validated server-side.",
                "severity": "MEDIUM",
                "recommendation": "Validate the Origin header against a strict allowlist.",
            })

    return findings


def analyse_security_headers(headers: dict) -> list:
    """Check for presence and basic misconfiguration of security headers."""
    findings = []

    for header_name, meta in SECURITY_HEADERS.items():
        value = headers.get(header_name)
        if value is None:
            findings.append({
                "header": header_name,
                "status": "FAIL",
                "value": "MISSING",
                "detail": f"{meta['description']} Header is absent.",
                "severity": meta["severity"],
                "recommendation": meta["recommendation"],
            })
        else:
            # Specific value checks
            issue = _check_header_value(header_name, value)
            if issue:
                findings.append({
                    "header": header_name,
                    "status": "WARN",
                    "value": value,
                    "detail": issue,
                    "severity": meta["severity"],
                    "recommendation": meta["recommendation"],
                })
            else:
                findings.append({
                    "header": header_name,
                    "status": "PASS",
                    "value": value,
                    "detail": meta["description"],
                })

    return findings


def _check_header_value(header: str, value: str) -> str | None:
    """Return a warning string if the header value looks weak, else None."""
    val = value.strip().lower()

    if header == "Strict-Transport-Security":
        # max-age should be at least 1 year (31536000)
        if "max-age=" in val:
            try:
                age = int(val.split("max-age=")[1].split(";")[0].strip())
                if age < 31536000:
                    return (f"HSTS max-age is {age}s (< 31536000). "
                            "OWASP recommends at least one year.")
            except (ValueError, IndexError):
                return "Could not parse HSTS max-age value."
        if "includesubdomains" not in val:
            return "HSTS is missing 'includeSubDomains' directive."

    elif header == "X-Frame-Options":
        if val not in ("deny", "sameorigin"):
            return f"Unexpected X-Frame-Options value: '{value}'. Use DENY or SAMEORIGIN."

    elif header == "X-Content-Type-Options":
        if val != "nosniff":
            return f"X-Content-Type-Options should be 'nosniff', got '{value}'."

    elif header == "Content-Security-Policy":
        if "unsafe-inline" in val:
            return "CSP contains 'unsafe-inline' which weakens XSS protection."
        if "unsafe-eval" in val:
            return "CSP contains 'unsafe-eval' which allows dynamic code execution."
        if val.startswith("default-src *") or val.startswith("default-src 'none'") is False:
            pass  # Basic check; full CSP parsing is complex

    elif header == "Referrer-Policy":
        safe_values = {
            "no-referrer", "same-origin", "strict-origin",
            "strict-origin-when-cross-origin", "no-referrer-when-downgrade",
        }
        if val not in safe_values:
            return f"Referrer-Policy value '{value}' may leak referrer data."

    return None


def analyse_information_disclosure(headers: dict) -> list:
    """Flag headers that reveal server/technology information."""
    findings = []

    for header_name, meta in DEPRECATED_HEADERS.items():
        value = headers.get(header_name)
        if value:
            findings.append({
                "header": header_name,
                "status": "WARN",
                "value": value,
                "detail": meta["description"],
                "severity": meta["severity"],
                "recommendation": meta["recommendation"],
            })

    return findings


# ──────────────────────────────────────────────
# Report rendering
# ──────────────────────────────────────────────
BANNER = r"""
   ██████╗ ██████╗ ██████╗ ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║     ██║   ██║██████╔╝███████╗    ███████╗██║     ███████║██╔██╗ ██║
  ██║     ██║   ██║██╔══██╗╚════██║    ╚════██║██║     ██╔══██╗██║╚██╗██║
  ╚██████╗╚██████╔╝██║  ██║███████║    ███████║╚██████╗██║  ██║██║ ╚████║
   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
        CORS & Security Header Scanner  ·  OWASP Best Practices
"""


def severity_color(severity: str) -> str:
    """Colour-code severity levels."""
    mapping = {"HIGH": Color.red, "MEDIUM": Color.yellow, "LOW": Color.dim}
    func = mapping.get(severity, Color.dim)
    return func(severity)


def print_banner():
    print(Color.cyan(BANNER))


def print_section(title: str):
    width = 64
    print(f"\n{'─' * width}")
    print(Color.bold(f"  ▸ {title}"))
    print(f"{'─' * width}")


def print_finding(finding: dict):
    header = finding["header"]
    status = finding["status"]
    value  = finding.get("value", "")
    detail = finding.get("detail", "")

    if status == "PASS":
        icon = Color.green("✔ SECURE")
    elif status == "FAIL":
        icon = Color.red("✘ VULNERABLE")
    elif status == "WARN":
        icon = Color.yellow("⚠ WARNING")
    else:
        icon = Color.cyan("ℹ INFO")

    print(f"\n  {icon}  {Color.bold(header)}")
    print(f"         Value   : {Color.dim(str(value))}")
    print(f"         Detail  : {detail}")

    if "severity" in finding:
        print(f"         Severity: {severity_color(finding['severity'])}")
    if "recommendation" in finding:
        wrapped = textwrap.fill(finding["recommendation"], width=55,
                                initial_indent="", subsequent_indent="                   ")
        print(f"         Fix     : {Color.cyan(wrapped)}")


def print_summary(findings: list):
    total = len(findings)
    passed  = sum(1 for f in findings if f["status"] == "PASS")
    failed  = sum(1 for f in findings if f["status"] == "FAIL")
    warned  = sum(1 for f in findings if f["status"] == "WARN")
    info    = sum(1 for f in findings if f["status"] == "INFO")

    print_section("SCAN SUMMARY")
    print(f"\n  Total checks  : {total}")
    print(f"  {Color.green('Passed')}       : {passed}")
    print(f"  {Color.red('Failed')}       : {failed}")
    print(f"  {Color.yellow('Warnings')}     : {warned}")
    print(f"  {Color.cyan('Informational')}: {info}")

    score = (passed / total * 100) if total > 0 else 0
    if score >= 80:
        grade_color = Color.green
    elif score >= 50:
        grade_color = Color.yellow
    else:
        grade_color = Color.red
    print(f"\n  Security Score : {grade_color(f'{score:.0f}%')}")

    if failed == 0 and warned == 0:
        print(f"\n  {Color.green('★ Excellent! No critical issues detected.')}")
    elif failed > 0:
        print(f"\n  {Color.red('⚑ Critical issues found — remediation recommended.')}")


def export_json(url: str, findings: list, output_file: str):
    """Export scan results to a JSON file."""
    report = {
        "scan_target": url,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "scanner": "CORS-Header-Scanner v1.0",
        "findings": findings,
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  {Color.green('✔')} Report saved to {Color.bold(output_file)}")


# ──────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="CORS & HTTP Security Header Scanner — OWASP Best Practices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              python cors_header_scanner.py https://example.com
              python cors_header_scanner.py https://example.com --timeout 15
              python cors_header_scanner.py https://example.com --json report.json
              python cors_header_scanner.py https://example.com --no-verify
        """),
    )
    parser.add_argument("url", help="Target URL to scan (include https://)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--json", dest="json_file", metavar="FILE",
                        help="Export results to a JSON file")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL certificate verification")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print_banner()
    print(f"  Target : {Color.bold(url)}")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Timeout: {args.timeout}s")

    # ── Fetch headers ──
    try:
        result = fetch_headers(url, timeout=args.timeout,
                               verify_ssl=not args.no_verify)
    except Timeout:
        print(f"\n  {Color.red('✘ ERROR')}: Connection timed out after {args.timeout}s.")
        print(f"         The target may be unreachable or blocking requests.")
        print(f"         Try increasing --timeout or verify the URL is correct.")
        sys.exit(1)
    except ConnectionError as e:
        print(f"\n  {Color.red('✘ ERROR')}: Could not connect to {url}")
        print(f"         {Color.dim(str(e))}")
        sys.exit(1)
    except RequestException as e:
        print(f"\n  {Color.red('✘ ERROR')}: Request failed — {e}")
        sys.exit(1)

    headers = result["headers"]
    print(f"  Status : {result['status_code']}")
    print(f"  Resolved: {result['url']}")
    print(f"  Latency: {result['elapsed']:.2f}s")

    all_findings = []

    # ── CORS Analysis ──
    print_section("CORS CONFIGURATION")
    cors_findings = analyse_cors(headers)
    all_findings.extend(cors_findings)
    for f in cors_findings:
        print_finding(f)

    # ── Security Headers ──
    print_section("SECURITY HEADERS (OWASP)")
    sec_findings = analyse_security_headers(headers)
    all_findings.extend(sec_findings)
    for f in sec_findings:
        print_finding(f)

    # ── Information Disclosure ──
    print_section("INFORMATION DISCLOSURE")
    info_findings = analyse_information_disclosure(headers)
    all_findings.extend(info_findings)
    if info_findings:
        for f in info_findings:
            print_finding(f)
    else:
        print(f"\n  {Color.green('✔')} No information-disclosure headers detected.")

    # ── Summary ──
    print_summary(all_findings)

    # ── JSON export ──
    if args.json_file:
        export_json(url, all_findings, args.json_file)

    print()


if __name__ == "__main__":
    main()
