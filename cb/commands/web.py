"""cb web - Web application security audit for AI security research."""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

from cb.output import add_output_args, make_formatter


# ---------------------------------------------------------------------------
# Security header definitions
# ---------------------------------------------------------------------------

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS not set — browsers may connect over HTTP",
        "recommended": "max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "description": "CSP not set — no protection against XSS/injection",
        "recommended": "default-src 'self'",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "Missing — browsers may MIME-sniff responses",
        "recommended": "nosniff",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Missing — vulnerable to clickjacking",
        "recommended": "DENY",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Missing — full URLs may leak in Referer headers",
        "recommended": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Missing — browser features not restricted",
        "recommended": "geolocation=(), camera=(), microphone=()",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "Missing — legacy XSS filter not enabled",
        "recommended": "1; mode=block",
    },
}

# Default paths for endpoint enumeration
DEFAULT_PATHS = [
    "robots.txt", "sitemap.xml", ".env", ".git/HEAD", ".git/config",
    ".well-known/security.txt", ".well-known/openid-configuration",
    "wp-login.php", "wp-admin/", "wp-json/wp/v2/users",
    "admin/", "administrator/", "login", "api/", "api/v1/",
    "graphql", "graphiql", "swagger.json", "openapi.json",
    "api-docs", "health", "healthz", "status", "metrics",
    "debug/", "trace", "server-status", "server-info",
    ".DS_Store", "backup/", "dump.sql", "config.php",
    "phpinfo.php",
]

# CSP directive risk scoring
CSP_UNSAFE_DIRECTIVES = {
    "'unsafe-inline'": {
        "severity": "high",
        "description": "Allows inline scripts/styles — defeats CSP's XSS protection",
    },
    "'unsafe-eval'": {
        "severity": "high",
        "description": "Allows eval() — enables dynamic code execution",
    },
    "*": {
        "severity": "high",
        "description": "Wildcard source — allows loading from any origin",
    },
    "data:": {
        "severity": "medium",
        "description": "Allows data: URIs — can be used for XSS payloads",
    },
    "http:": {
        "severity": "medium",
        "description": "Allows HTTP sources — content may be tampered in transit",
    },
}


# ---------------------------------------------------------------------------
# CLI registration
# ---------------------------------------------------------------------------

def register(subparsers):
    p = subparsers.add_parser("web", help="Web application security audit")
    sub = p.add_subparsers(dest="web_command", help="Web audit subcommands")

    # --- headers ---
    s = sub.add_parser("headers", help="Analyze HTTP security headers")
    s.add_argument("url", help="Target URL")
    s.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10s)")
    add_output_args(s)

    # --- endpoints ---
    s = sub.add_parser("endpoints", help="Enumerate common endpoints")
    s.add_argument("url", help="Base URL")
    s.add_argument("--wordlist", type=str, default=None,
                   help="Custom wordlist file (one path per line)")
    s.add_argument("--max-requests", type=int, default=50,
                   help="Maximum requests to send (default: 50)")
    s.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10s)")
    add_output_args(s)

    # --- cors ---
    s = sub.add_parser("cors", help="Test for CORS misconfigurations")
    s.add_argument("url", help="Target URL")
    s.add_argument("--origins", type=str, nargs="+",
                   default=["https://evil.com", "null", "https://attacker.example.com"],
                   help="Test origins to send")
    s.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10s)")
    add_output_args(s)

    # --- csp ---
    s = sub.add_parser("csp", help="Analyze Content Security Policy")
    s.add_argument("url", help="Target URL (or pass CSP string directly via --policy)")
    s.add_argument("--policy", type=str, default=None,
                   help="CSP policy string to analyze (instead of fetching from URL)")
    s.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10s)")
    add_output_args(s)

    # --- cookies ---
    s = sub.add_parser("cookies", help="Analyze cookie security attributes")
    s.add_argument("url", help="Target URL")
    s.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10s)")
    add_output_args(s)

    # --- scan ---
    s = sub.add_parser("scan", help="Full security scan (all checks)")
    s.add_argument("url", help="Target URL")
    s.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10s)")
    s.add_argument("--max-requests", type=int, default=50,
                   help="Maximum endpoint requests (default: 50)")
    add_output_args(s)

    p.set_defaults(func=run)


# ---------------------------------------------------------------------------
# Top-level dispatcher
# ---------------------------------------------------------------------------

def run(args):
    out = make_formatter(args)

    cmd = getattr(args, "web_command", None)
    if not cmd:
        print("usage: cb web {headers,endpoints,cors,csp,cookies,scan} ...",
              file=sys.stderr)
        sys.exit(1)

    if cmd == "headers":
        _run_headers(args, out)
    elif cmd == "endpoints":
        _run_endpoints(args, out)
    elif cmd == "cors":
        _run_cors(args, out)
    elif cmd == "csp":
        _run_csp(args, out)
    elif cmd == "cookies":
        _run_cookies(args, out)
    elif cmd == "scan":
        _run_scan(args, out)
    else:
        print(f"Unknown web subcommand: {cmd}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def _run_headers(args, out):
    url = args.url
    timeout = getattr(args, "timeout", 10)
    out.status(f"Analyzing security headers for {url}...")

    status_code, headers, error = _fetch(url, timeout=timeout)
    if error:
        out.emit({"url": url, "error": error}, "web")
        return

    findings = analyze_security_headers(headers)
    result = {
        "url": url,
        "status_code": status_code,
        "headers_present": {k: v for k, v in headers.items()
                           if k in SECURITY_HEADERS},
        "findings": findings,
        "total_findings": len(findings),
    }
    out.emit(result, "web")


def _run_endpoints(args, out):
    url = args.url.rstrip("/")
    timeout = getattr(args, "timeout", 10)
    max_requests = getattr(args, "max_requests", 50)
    out.status(f"Enumerating endpoints on {url}...")

    wordlist = DEFAULT_PATHS
    wl_file = getattr(args, "wordlist", None)
    if wl_file and os.path.isfile(wl_file):
        with open(wl_file) as f:
            wordlist = [line.strip() for line in f if line.strip()]

    found = enumerate_endpoints(url, wordlist=wordlist,
                                max_requests=max_requests, timeout=timeout)
    result = {
        "url": url,
        "paths_tested": min(len(wordlist), max_requests),
        "endpoints_found": found,
        "total_found": len(found),
    }
    out.emit(result, "web")


def _run_cors(args, out):
    url = args.url
    test_origins = getattr(args, "origins", ["https://evil.com"])
    timeout = getattr(args, "timeout", 10)
    out.status(f"Testing CORS configuration on {url}...")

    findings = analyze_cors(url, test_origins=test_origins, timeout=timeout)
    result = {
        "url": url,
        "test_origins": test_origins,
        "findings": findings,
        "total_findings": len(findings),
    }
    out.emit(result, "web")


def _run_csp(args, out):
    url = args.url
    timeout = getattr(args, "timeout", 10)
    policy_str = getattr(args, "policy", None)

    if policy_str is None:
        out.status(f"Fetching CSP from {url}...")
        status_code, headers, error = _fetch(url, timeout=timeout)
        if error:
            out.emit({"url": url, "error": error}, "web")
            return
        policy_str = headers.get("Content-Security-Policy", "")
        if not policy_str:
            out.emit({
                "url": url,
                "csp_present": False,
                "findings": [{"severity": "high",
                              "description": "No Content-Security-Policy header found"}],
            }, "web")
            return

    findings = analyze_csp(policy_str)
    result = {
        "url": url,
        "csp_present": True,
        "policy": policy_str,
        "findings": findings,
        "total_findings": len(findings),
    }
    out.emit(result, "web")


def _run_cookies(args, out):
    url = args.url
    timeout = getattr(args, "timeout", 10)
    out.status(f"Analyzing cookies from {url}...")

    status_code, headers, error = _fetch(url, timeout=timeout)
    if error:
        out.emit({"url": url, "error": error}, "web")
        return

    # Collect all Set-Cookie headers
    set_cookies = _get_all_set_cookies(headers)
    if not set_cookies:
        out.emit({"url": url, "cookies_found": 0, "findings": []}, "web")
        return

    findings = analyze_cookies(set_cookies)
    result = {
        "url": url,
        "cookies_found": len(set_cookies),
        "cookie_headers": set_cookies,
        "findings": findings,
        "total_findings": len(findings),
    }
    out.emit(result, "web")


def _run_scan(args, out):
    url = args.url
    timeout = getattr(args, "timeout", 10)
    max_requests = getattr(args, "max_requests", 50)
    out.status(f"Running full security scan on {url}...")

    sections = {}

    # Headers
    out.status("  Checking security headers...")
    status_code, headers, error = _fetch(url, timeout=timeout)
    if error:
        sections["headers"] = {"error": error}
    else:
        header_findings = analyze_security_headers(headers)
        sections["headers"] = {
            "status_code": status_code,
            "findings": header_findings,
        }

        # CSP
        out.status("  Analyzing CSP...")
        csp = headers.get("Content-Security-Policy", "")
        if csp:
            sections["csp"] = {
                "policy": csp,
                "findings": analyze_csp(csp),
            }
        else:
            sections["csp"] = {
                "csp_present": False,
                "findings": [{"severity": "high",
                              "description": "No Content-Security-Policy header"}],
            }

        # Cookies
        out.status("  Analyzing cookies...")
        set_cookies = _get_all_set_cookies(headers)
        if set_cookies:
            sections["cookies"] = {
                "cookies_found": len(set_cookies),
                "findings": analyze_cookies(set_cookies),
            }

        # CORS
        out.status("  Testing CORS...")
        cors_findings = analyze_cors(url, timeout=timeout)
        sections["cors"] = {"findings": cors_findings}

    # Endpoints
    out.status("  Enumerating endpoints...")
    found = enumerate_endpoints(url.rstrip("/"), max_requests=max_requests,
                                timeout=timeout)
    sections["endpoints"] = {
        "total_found": len(found),
        "endpoints": found,
    }

    # Aggregate findings
    all_findings = []
    for section_name, section_data in sections.items():
        for f in section_data.get("findings", []):
            f["source"] = section_name
            all_findings.append(f)

    result = {
        "url": url,
        "sections": sections,
        "total_findings": len(all_findings),
        "findings_by_severity": {
            "high": sum(1 for f in all_findings if f.get("severity") == "high"),
            "medium": sum(1 for f in all_findings if f.get("severity") == "medium"),
            "low": sum(1 for f in all_findings if f.get("severity") == "low"),
        },
    }
    out.emit(result, "web")


# ---------------------------------------------------------------------------
# Core analysis functions
# ---------------------------------------------------------------------------

def _fetch(url, method="GET", headers=None, timeout=10):
    """Fetch a URL using stdlib urllib.request.

    Returns (status_code, headers_dict, error_string_or_None).
    """
    req_headers = {"User-Agent": "catbyte-toolkit/0.1.0"}
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, method=method, headers=req_headers)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        resp_headers = {k: v for k, v in resp.getheaders()}
        return resp.status, resp_headers, None
    except urllib.error.HTTPError as e:
        resp_headers = {k: v for k, v in e.headers.items()} if e.headers else {}
        return e.code, resp_headers, None
    except urllib.error.URLError as e:
        return None, {}, f"Connection error: {e.reason}"
    except Exception as e:
        return None, {}, str(e)


def _get_all_set_cookies(headers):
    """Extract Set-Cookie header values.

    urllib collapses multiple Set-Cookie headers, so we handle both
    single and comma-separated values.
    """
    raw = headers.get("Set-Cookie", "")
    if not raw:
        return []
    # Split on comma but not within expires date values
    # Simple approach: split by comma followed by space and a cookie name pattern
    cookies = []
    for part in re.split(r",\s*(?=[A-Za-z_][\w]*=)", raw):
        part = part.strip()
        if part:
            cookies.append(part)
    return cookies if cookies else [raw]


def analyze_security_headers(headers):
    """Check for missing or misconfigured security headers.

    Parameters
    ----------
    headers : dict
        HTTP response headers (case-sensitive keys).

    Returns
    -------
    list[dict]
        Findings for missing or misconfigured headers.
    """
    findings = []
    # Normalize header lookup (case-insensitive)
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header_name, info in SECURITY_HEADERS.items():
        value = lower_headers.get(header_name.lower(), None)
        if value is None:
            findings.append({
                "header": header_name,
                "severity": info["severity"],
                "description": f"Missing: {info['description']}",
                "recommended": info["recommended"],
                "status": "missing",
            })
        else:
            # Check for weak values
            if header_name == "Strict-Transport-Security":
                if "max-age=0" in value:
                    findings.append({
                        "header": header_name,
                        "severity": "high",
                        "description": "HSTS max-age is 0 — effectively disabled",
                        "current_value": value,
                        "status": "weak",
                    })
            elif header_name == "X-Content-Type-Options":
                if value.lower() != "nosniff":
                    findings.append({
                        "header": header_name,
                        "severity": "medium",
                        "description": f"Unexpected value: {value}",
                        "current_value": value,
                        "status": "weak",
                    })

    return findings


def analyze_csp(csp_value):
    """Parse and analyze a Content Security Policy string.

    Parameters
    ----------
    csp_value : str
        The CSP header value.

    Returns
    -------
    list[dict]
        Findings for unsafe or misconfigured directives.
    """
    findings = []
    if not csp_value:
        findings.append({
            "severity": "high",
            "description": "Empty CSP policy",
            "directive": None,
        })
        return findings

    # Parse directives
    directives = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directive_name = tokens[0].lower()
            directive_values = tokens[1:] if len(tokens) > 1 else []
            directives[directive_name] = directive_values

    # Check for missing default-src
    if "default-src" not in directives:
        findings.append({
            "severity": "medium",
            "description": "No default-src directive — fallback behavior undefined",
            "directive": "default-src",
        })

    # Check each directive for unsafe values
    for directive, values in directives.items():
        for value in values:
            value_lower = value.lower()
            for unsafe_pattern, info in CSP_UNSAFE_DIRECTIVES.items():
                if value_lower == unsafe_pattern.lower():
                    findings.append({
                        "severity": info["severity"],
                        "description": f"{directive}: {info['description']}",
                        "directive": directive,
                        "value": value,
                    })

    return findings


def analyze_cors(url, test_origins=None, timeout=10):
    """Test for CORS misconfigurations by sending crafted Origin headers.

    Parameters
    ----------
    url : str
        Target URL.
    test_origins : list[str]
        Origins to test (default: evil.com, null, attacker.example.com).
    timeout : int
        Request timeout in seconds.

    Returns
    -------
    list[dict]
        Findings for CORS misconfigurations.
    """
    if test_origins is None:
        test_origins = ["https://evil.com", "null",
                        "https://attacker.example.com"]

    findings = []

    for origin in test_origins:
        status_code, headers, error = _fetch(
            url, headers={"Origin": origin}, timeout=timeout)
        if error:
            continue

        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            findings.append({
                "severity": "medium",
                "description": "ACAO is wildcard (*) — any origin can read responses",
                "origin_tested": origin,
                "acao": acao,
            })
        elif acao and acao.lower() == origin.lower():
            severity = "high" if acac.lower() == "true" else "medium"
            findings.append({
                "severity": severity,
                "description": (f"Origin {origin} is reflected in ACAO"
                               + (" with credentials" if acac.lower() == "true" else "")),
                "origin_tested": origin,
                "acao": acao,
                "credentials": acac.lower() == "true",
            })

        if origin == "null" and acao == "null":
            findings.append({
                "severity": "high",
                "description": "ACAO reflects 'null' origin — sandboxed iframe bypass",
                "origin_tested": origin,
                "acao": acao,
            })

    return findings


def analyze_cookies(set_cookie_headers):
    """Analyze Set-Cookie headers for security attribute issues.

    Parameters
    ----------
    set_cookie_headers : list[str]
        Raw Set-Cookie header values.

    Returns
    -------
    list[dict]
        Findings for missing or misconfigured cookie attributes.
    """
    findings = []

    for cookie_str in set_cookie_headers:
        # Parse cookie name
        name_match = re.match(r"([^=]+)=", cookie_str)
        cookie_name = name_match.group(1).strip() if name_match else "unknown"

        attrs_lower = cookie_str.lower()

        if "; secure" not in attrs_lower and ";secure" not in attrs_lower:
            if not attrs_lower.startswith("secure"):
                findings.append({
                    "severity": "high",
                    "description": f"Cookie '{cookie_name}' missing Secure flag — sent over HTTP",
                    "cookie": cookie_name,
                    "attribute": "Secure",
                })

        if "; httponly" not in attrs_lower and ";httponly" not in attrs_lower:
            findings.append({
                "severity": "high",
                "description": f"Cookie '{cookie_name}' missing HttpOnly — accessible via JavaScript",
                "cookie": cookie_name,
                "attribute": "HttpOnly",
            })

        if "samesite" not in attrs_lower:
            findings.append({
                "severity": "medium",
                "description": f"Cookie '{cookie_name}' missing SameSite — CSRF risk",
                "cookie": cookie_name,
                "attribute": "SameSite",
            })
        elif "samesite=none" in attrs_lower:
            findings.append({
                "severity": "medium",
                "description": f"Cookie '{cookie_name}' has SameSite=None — sent on cross-site requests",
                "cookie": cookie_name,
                "attribute": "SameSite",
            })

    return findings


def enumerate_endpoints(base_url, wordlist=None, max_requests=50, timeout=10):
    """Probe common paths on a web server.

    Parameters
    ----------
    base_url : str
        Base URL without trailing slash.
    wordlist : list[str]
        Paths to test (default: DEFAULT_PATHS).
    max_requests : int
        Maximum number of requests to send.
    timeout : int
        Request timeout per request in seconds.

    Returns
    -------
    list[dict]
        Found endpoints with status codes.
    """
    if wordlist is None:
        wordlist = DEFAULT_PATHS

    found = []
    for path in wordlist[:max_requests]:
        url = f"{base_url}/{path}"
        try:
            req = urllib.request.Request(
                url, method="GET",
                headers={"User-Agent": "catbyte-toolkit/0.1.0"})
            resp = urllib.request.urlopen(req, timeout=timeout)
            found.append({
                "path": f"/{path}",
                "url": url,
                "status": resp.status,
                "content_type": resp.headers.get("Content-Type", ""),
            })
        except urllib.error.HTTPError as e:
            if e.code not in (404, 405, 403):
                found.append({
                    "path": f"/{path}",
                    "url": url,
                    "status": e.code,
                    "content_type": e.headers.get("Content-Type", "") if e.headers else "",
                })
        except (urllib.error.URLError, Exception):
            continue

    return found


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="cbweb",
        description="Web application security audit",
    )
    sub = parser.add_subparsers(dest="web_command")

    s = sub.add_parser("headers", help="Analyze security headers")
    s.add_argument("url")
    s.add_argument("--timeout", type=int, default=10)
    add_output_args(s)

    s = sub.add_parser("endpoints", help="Enumerate endpoints")
    s.add_argument("url")
    s.add_argument("--wordlist", type=str, default=None)
    s.add_argument("--max-requests", type=int, default=50)
    s.add_argument("--timeout", type=int, default=10)
    add_output_args(s)

    s = sub.add_parser("cors", help="Test CORS")
    s.add_argument("url")
    s.add_argument("--origins", type=str, nargs="+",
                   default=["https://evil.com", "null"])
    s.add_argument("--timeout", type=int, default=10)
    add_output_args(s)

    s = sub.add_parser("csp", help="Analyze CSP")
    s.add_argument("url")
    s.add_argument("--policy", type=str, default=None)
    s.add_argument("--timeout", type=int, default=10)
    add_output_args(s)

    s = sub.add_parser("cookies", help="Analyze cookies")
    s.add_argument("url")
    s.add_argument("--timeout", type=int, default=10)
    add_output_args(s)

    s = sub.add_parser("scan", help="Full scan")
    s.add_argument("url")
    s.add_argument("--timeout", type=int, default=10)
    s.add_argument("--max-requests", type=int, default=50)
    add_output_args(s)

    args = parser.parse_args()
    if not args.web_command:
        parser.print_help()
        sys.exit(1)
    run(args)


if __name__ == "__main__":
    main()
