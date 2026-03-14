#!/usr/bin/env python3

import argparse
import base64
import json
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

# Ensure imports work regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Suppress SSL warnings globally
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests

from core.display import (
    show_banner,
    print_found,
    print_info,
    print_warn,
    print_error,
    print_success,
    print_section,
    print_severity_summary,
    print_severity_group,
)
from core.crawler import fetch_robots, fetch_sitemap, discover_js_files
from core.js_scanner import scan_js_file
from core.bruteforcer import (
    load_wordlist,
    bruteforce,
    detect_waf,
    check_path,
    test_http_methods,
    get_soft_404_baseline,
    generate_versioned_paths,
)
from core.severity import score_endpoint, sort_by_severity, get_severity_stats, SEVERITY_ORDER

# Optional imports — gracefully degrade if missing
try:
    from core.cors_scanner import scan_cors_bulk
    HAS_CORS_SCANNER = True
except ImportError:
    HAS_CORS_SCANNER = False

try:
    from core.jwt_tester import extract_jwts_from_results, test_jwt_none_algorithm, test_jwt_weak_secret
    HAS_JWT_TESTER = True
except ImportError:
    HAS_JWT_TESTER = False


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "PostmanRuntime/7.36.3",
    "python-requests/2.31.0",
    "curl/8.5.0",
]

def parse_args():
    parser = argparse.ArgumentParser(
        prog="api_discovery",
        description="API-Discovery v2.0 — Hidden API Endpoint Finder",
        epilog=(
            "Examples:\n"
            "  python api_discovery.py -u https://target.com -t 20 --delay 1\n"
            "  python api_discovery.py -u https://target.com --cookie \"session=abc\"\n"
            "  python api_discovery.py -u https://target.com --auth-type bearer --auth-token TOKEN\n"
            "  python api_discovery.py -u https://target.com --version-fuzz --resume\n"
            "  python api_discovery.py -u https://target.com --header \"X-Custom: value\" --header \"X-Other: val2\"\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-u", "--url", help="Target base URL (e.g. https://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("-w", "--wordlist", help="Path to a custom wordlist file (default: built-in 700+ paths)")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP request timeout in seconds (default: 5)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds (default: 0)")
    parser.add_argument("--user-agent", help="Custom User-Agent header string")
    parser.add_argument("-o", "--output", default="api_discovery_report", help="Output report file name without extension (default: api_discovery_report)")

    parser.add_argument("--no-js", action="store_true", help="Skip JavaScript file scanning")
    parser.add_argument("--no-robots", action="store_true", help="Skip robots.txt and sitemap.xml checks")
    parser.add_argument("--no-brute", action="store_true", help="Skip wordlist brute-forcing")
    parser.add_argument("--status-codes",
                        type=lambda s: [int(x.strip()) for x in s.split(",")],
                        default=[200, 201, 301, 302, 403, 405, 500],
                        help="Comma-separated status codes to report (default: 200,201,301,302,403,405,500)")
    parser.add_argument("--show-all", action="store_true", help="Show all severity levels in detail")
    parser.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        default="HIGH", help="Minimum severity level to show in detail (default: HIGH)")

    parser.add_argument("--waf-aggressive", action="store_true",
                        help="Use aggressive WAF detection with XSS/SQLi payloads (may trigger blocks)")

    parser.add_argument("--cookie", help='Cookie header value, e.g. "name=value; name2=value2"')
    parser.add_argument("--header", action="append", dest="extra_headers",
                        help='Custom header, e.g. "Authorization: Bearer TOKEN" (can be used multiple times)')
    parser.add_argument("--auth-type", choices=["bearer", "basic", "cookie", "custom"],
                        help="Authentication type: bearer, basic, cookie, or custom")
    parser.add_argument("--auth-token", help="Authentication token or credentials for --auth-type")

    parser.add_argument("--version-fuzz", action="store_true",
                        help="After brute-force, fuzz discovered paths with API version variants (v1-v5, latest, beta, etc.)")

    parser.add_argument("--resume", action="store_true",
                        help="Resume a previously interrupted scan from the progress file")

    return parser.parse_args()

def build_auth_headers(args):
    """
    Build a headers dict from the parsed authentication CLI flags.

    Supports:
    - Bearer token
    - Basic auth (base64 encoded)
    - Raw cookie header
    - Custom header injection via --header
    """
    auth_headers = {}

    # --cookie flag
    if args.cookie:
        auth_headers["Cookie"] = args.cookie

    # --auth-type + --auth-token
    if args.auth_type and args.auth_token:
        if args.auth_type == "bearer":
            auth_headers["Authorization"] = f"Bearer {args.auth_token}"
        elif args.auth_type == "basic":
            # Expect auth_token as "user:pass"
            try:
                encoded = base64.b64encode(args.auth_token.encode("utf-8")).decode("utf-8")
                auth_headers["Authorization"] = f"Basic {encoded}"
            except Exception:
                pass
        elif args.auth_type == "cookie":
            auth_headers["Cookie"] = args.auth_token
        elif args.auth_type == "custom":
            # Expect auth_token as "Header-Name: value"
            if ":" in args.auth_token:
                key, _, val = args.auth_token.partition(":")
                auth_headers[key.strip()] = val.strip()

    # --header flags (repeatable)
    if args.extra_headers:
        for h in args.extra_headers:
            if ":" in h:
                key, _, val = h.partition(":")
                auth_headers[key.strip()] = val.strip()

    return auth_headers


def validate_url(url):
    """Validate and normalize the target URL."""
    if not url:
        return None

    url = url.strip().rstrip("/")

    # Auto-add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
        return url
    except Exception:
        return None


def get_default_wordlist():
    """Return absolute path to the built-in wordlist."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "api_paths.txt")


def build_url(base_url, path):
    """Safely concatenate base URL and path, avoiding double slashes."""
    return base_url.rstrip("/") + ("/" + path.lstrip("/") if not path.startswith("/") else path)


def _verify_path(target_url, r, timeout, headers, allowed_codes, baseline):
    """Verify a single discovered path. Module-level helper for Phase 4."""
    try:
        cr = check_path(target_url, r["path"], timeout, headers, 0, baseline)
        r["status"] = cr["status"]
        r["length"] = cr["length"]
        r["redirect"] = cr["redirect"]
        return cr["status"] in allowed_codes
    except Exception:
        r["status"] = 0
        return False

def save_progress(checked_paths, found_results, output_name, target_url):
    """
    Save scan progress to {output_name}.progress.json.
    Called periodically so scans can be resumed after interruption.
    """
    progress_file = f"{output_name}.progress.json"
    data = {
        "target_url": target_url,
        "timestamp": datetime.now().isoformat(),
        "checked_paths": list(checked_paths),
        "found_results": found_results,
    }
    try:
        with open(progress_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception:
        pass


def load_progress(output_name, target_url):
    """
    Load progress file if it exists and the target URL matches.
    Returns (checked_paths_set, partial_results_list) or (set(), []).
    """
    progress_file = f"{output_name}.progress.json"

    if not os.path.exists(progress_file):
        return set(), []

    try:
        with open(progress_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Validate target URL matches
        if data.get("target_url") != target_url:
            return set(), []

        checked = set(data.get("checked_paths", []))
        results = data.get("found_results", [])
        return checked, results

    except Exception:
        return set(), []


def delete_progress(output_name):
    """Delete the progress file after scan completes."""
    progress_file = f"{output_name}.progress.json"
    try:
        if os.path.exists(progress_file):
            os.remove(progress_file)
    except Exception:
        pass

def _redact_secret(value):
    """Redact a secret value: show first 4 and last 4 chars, mask the middle."""
    if not value or len(value) <= 12:
        return "****"
    return value[:4] + "*" * min(len(value) - 8, 20) + value[-4:]


def save_report(results, secrets, target_url, output_name, stats, elapsed, cors_findings=None, jwt_findings=None):
    """Save results to .txt, .json, and .md report files."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    txt_path = f"{output_name}.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 64 + "\n")
        f.write("  API-DISCOVERY v2.0 — SCAN REPORT\n")
        f.write("=" * 64 + "\n")
        f.write(f"  Target    : {target_url}\n")
        f.write(f"  Timestamp : {timestamp}\n")
        f.write(f"  Duration  : {elapsed:.1f}s\n")
        f.write(f"  Total     : {stats.get('total', 0)} endpoints\n")
        f.write("=" * 64 + "\n\n")

        f.write("  SEVERITY SUMMARY\n")
        f.write("  " + "-" * 36 + "\n")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            f.write(f"    [{sev:>8}] : {stats.get(sev, 0)}\n")
        f.write("  " + "-" * 36 + "\n\n")

        f.write("  DISCOVERED ENDPOINTS\n")
        f.write("  " + "-" * 60 + "\n")
        for r in results:
            sev = r.get("severity", "INFO")
            path = r.get("path", "")
            status = r.get("status", "N/A")
            source = r.get("source", "unknown")
            reason = r.get("severity_reason", "")
            f.write(f"  [{sev:>8}] [{status}] {path}\n")
            f.write(f"              Source: {source}\n")
            if reason:
                f.write(f"              Reason: {reason}\n")
            f.write("\n")

        if secrets:
            f.write("\n  SECRETS FOUND\n")
            f.write("  " + "-" * 60 + "\n")
            for s in secrets:
                f.write(f"    Type    : {s.get('type', 'Unknown')}\n")
                val = s.get("value", "N/A")
                if len(val) > 80:
                    val = val[:80] + "..."
                f.write(f"    Value   : {val}\n")
                f.write(f"    File    : {s.get('file', 'N/A')}\n")
                ctx = s.get("context", "N/A")
                if len(ctx) > 120:
                    ctx = ctx[:120] + "..."
                f.write(f"    Context : {ctx}\n\n")

        if cors_findings:
            f.write("\n  CORS MISCONFIGURATIONS\n")
            f.write("  " + "-" * 60 + "\n")
            for cf in cors_findings:
                f.write(f"    [{cf['severity']:>8}] {cf['url']}\n")
                f.write(f"              {cf['description']}\n\n")

        if jwt_findings:
            f.write("\n  JWT VULNERABILITIES\n")
            f.write("  " + "-" * 60 + "\n")
            for jf in jwt_findings:
                f.write(f"    {jf}\n")

    json_path = f"{output_name}.json"
    report = {
        "tool": "API-Discovery v2.0",
        "target": target_url,
        "timestamp": timestamp,
        "duration_seconds": round(elapsed, 1),
        "severity_stats": stats,
        "endpoints": results,
        "secrets": secrets,
        "cors_findings": cors_findings or [],
        "jwt_findings": jwt_findings or [],
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    md_path = f"{output_name}.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# API-Discovery v2.0 — Scan Report\n\n")
        f.write(f"| Field | Value |\n")
        f.write(f"|-------|-------|\n")
        f.write(f"| **Target** | `{target_url}` |\n")
        f.write(f"| **Timestamp** | {timestamp} |\n")
        f.write(f"| **Duration** | {elapsed:.1f}s |\n")
        f.write(f"| **Total Endpoints** | {stats.get('total', 0)} |\n\n")

        # Severity summary table
        f.write("## Severity Summary\n\n")
        f.write("| Severity | Count |\n")
        f.write("|----------|-------|\n")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = stats.get(sev, 0)
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}.get(sev, "")
            f.write(f"| {emoji} **{sev}** | {count} |\n")
        f.write(f"| **TOTAL** | **{stats.get('total', 0)}** |\n\n")

        # Each severity group
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            sev_results = [r for r in results if r.get("severity") == sev]
            if not sev_results:
                continue

            f.write(f"## {sev} — {len(sev_results)} endpoint(s)\n\n")
            f.write("| Path | Status | Source | Reason |\n")
            f.write("|------|--------|--------|--------|\n")
            for r in sev_results:
                path = r.get("path", "").replace("|", "\\|")
                status = r.get("status", "N/A")
                source = r.get("source", "unknown")
                reason = r.get("severity_reason", "").replace("|", "\\|")
                f.write(f"| `{path}` | {status} | {source} | {reason} |\n")
            f.write("\n")

        # Secrets section with redacted values
        if secrets:
            f.write("## Secrets Found\n\n")
            f.write("| Type | Value (Redacted) | File |\n")
            f.write("|------|------------------|------|\n")
            for s in secrets:
                stype = s.get("type", "Unknown").replace("|", "\\|")
                raw_val = s.get("value", "N/A")
                redacted = _redact_secret(raw_val)
                sfile = s.get("file", "N/A").split("/")[-1].split("?")[0].replace("|", "\\|")
                f.write(f"| {stype} | `{redacted}` | {sfile} |\n")
            f.write("\n")

        # CORS findings
        if cors_findings:
            f.write("## CORS Misconfigurations\n\n")
            f.write("| URL | Severity | Description |\n")
            f.write("|-----|----------|-------------|\n")
            for cf in cors_findings:
                curl = cf.get("url", "").replace("|", "\\|")
                csev = cf.get("severity", "")
                cdesc = cf.get("description", "").replace("|", "\\|")
                f.write(f"| `{curl}` | {csev} | {cdesc} |\n")
            f.write("\n")

        # JWT findings
        if jwt_findings:
            f.write("## JWT Vulnerabilities\n\n")
            for jf in jwt_findings:
                f.write(f"- {jf}\n")
            f.write("\n")

        f.write("---\n\n")
        f.write("*Generated by API-Discovery v2.0 — For Authorized Testing Only*\n")

    return txt_path, json_path, md_path

def main():
    args = parse_args()

    show_banner()

    target_url = args.url
    if not target_url:
        print_info("Interactive mode — no --url flag provided.\n")
        try:
            target_url = input("  Enter target URL: ").strip()
        except (KeyboardInterrupt, EOFError):
            print_error("\nExiting.")
            sys.exit(1)

    target_url = validate_url(target_url)
    if not target_url:
        print_error("Invalid URL. Provide a valid URL like https://example.com")
        sys.exit(1)

    allowed_codes = args.status_codes

    user_agent = args.user_agent if args.user_agent else random.choice(USER_AGENTS)
    headers = {"User-Agent": user_agent}

    auth_headers = build_auth_headers(args)
    headers.update(auth_headers)

    print_section("SCAN CONFIGURATION")
    print_info(f"Target URL   : {target_url}")
    print_info(f"Threads      : {args.threads}")
    print_info(f"Timeout      : {args.timeout}s")
    print_info(f"Delay        : {args.delay}s")
    ua_display = user_agent[:55] + "..." if len(user_agent) > 55 else user_agent
    print_info(f"User-Agent   : {ua_display}")
    print_info(f"Status Codes : {','.join(str(c) for c in allowed_codes)}")
    print_info(f"Output       : {args.output}.txt / .json / .md")

    if auth_headers:
        auth_types = list(auth_headers.keys())
        print_info(f"Auth Headers : {', '.join(auth_types)}")
    if args.version_fuzz:
        print_info("Version Fuzz : ENABLED")
    if args.resume:
        print_info("Resume Mode  : ENABLED")

    print()
    print_warn("Use only on systems you own or have written permission to test!")
    print()

    print_info("Checking target connectivity...")
    try:
        resp = requests.get(target_url, headers=headers, timeout=args.timeout, verify=False)
        print_success(f"Target is reachable — HTTP {resp.status_code}")
    except requests.exceptions.ConnectionError:
        print_error(f"Cannot connect to {target_url} — check the URL and try again.")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print_error(f"Connection to {target_url} timed out.")
        sys.exit(1)
    except Exception as e:
        print_error(f"Error connecting to target: {e}")
        sys.exit(1)

    all_results = []
    all_secrets = []
    discovered_paths = set()
    baseline = None
    start_time = time.time()
    cors_findings = []
    jwt_findings = []

    resumed_paths = set()
    if args.resume:
        resumed_paths, resumed_results = load_progress(args.output, target_url)
        if resumed_paths:
            print_success(f"Resumed — {len(resumed_paths)} paths already checked, {len(resumed_results)} results loaded")
            all_results.extend(resumed_results)
            discovered_paths.update(resumed_paths)
        else:
            print_info("No progress file found — starting fresh scan")
    if not args.no_robots:
        print_section("PHASE 1 — ROBOTS.TXT & SITEMAP.XML")

        print_info("Checking robots.txt...")
        robots_data = fetch_robots(target_url, args.timeout, headers)

        if robots_data["paths"]:
            print_success(f"robots.txt found — {len(robots_data['paths'])} paths extracted")
            for path in robots_data["paths"]:
                if path not in discovered_paths:
                    discovered_paths.add(path)
                    all_results.append({
                        "path": path,
                        "url": build_url(target_url, path),
                        "status": "N/A",
                        "length": 0,
                        "redirect": None,
                        "source": "robots.txt",
                    })
        else:
            print_error("robots.txt not found or empty")

        sitemap_urls = robots_data.get("sitemaps", [])
        if not sitemap_urls:
            sitemap_urls = [target_url.rstrip("/") + "/sitemap.xml"]

        for sm_url in sitemap_urls:
            short_name = sm_url.split("/")[-1] if "/" in sm_url else sm_url
            print_info(f"Checking {short_name}...")
            sitemap_paths = fetch_sitemap(sm_url, args.timeout, headers)

            if sitemap_paths:
                print_success(f"{short_name} found — {len(sitemap_paths)} paths extracted")
                for path in sitemap_paths:
                    if path not in discovered_paths:
                        discovered_paths.add(path)
                        all_results.append({
                            "path": path,
                            "url": build_url(target_url, path),
                            "status": "N/A",
                            "length": 0,
                            "redirect": None,
                            "source": "sitemap.xml",
                        })
            else:
                print_error(f"{short_name} not found")    if not args.no_js:
        print_section("PHASE 2 — JAVASCRIPT SCANNING")

        print_info("Discovering JS files...")
        js_files = discover_js_files(target_url, args.timeout, headers)

        if js_files:
            print_success(f"Found {len(js_files)} JS files")
            print_info("Scanning JS files for API paths and secrets...")

            js_paths_count = 0
            js_secrets_count = 0
            seen_global_secrets = set()

            for js_url in js_files:
                scan_result = scan_js_file(js_url, args.timeout, headers)

                for path in scan_result["paths"]:
                    if path not in discovered_paths:
                        discovered_paths.add(path)
                        full_url = build_url(target_url, path) if path.startswith("/") else path
                        all_results.append({
                            "path": path,
                            "url": full_url,
                            "status": "N/A",
                            "length": 0,
                            "redirect": None,
                            "source": "js_scan",
                        })
                        js_paths_count += 1

                for secret in scan_result["secrets"]:
                    secret_key = (secret["type"], secret["value"])
                    if secret_key not in seen_global_secrets:
                        seen_global_secrets.add(secret_key)
                        secret["file"] = js_url
                        all_secrets.append(secret)
                        js_secrets_count += 1

            print_success(f"JS scan complete — {js_paths_count} paths, {js_secrets_count} secrets found")

            # Display discovered secrets with warnings
            if all_secrets:
                print()
                for s in all_secrets:
                    fname = s.get("file", "unknown")
                    fname = fname.split("/")[-1] if "/" in fname else fname
                    fname = fname.split("?")[0]  # remove query string
                    print_warn(f"SECRET FOUND in {fname}")
                    print(f"            Type  : {s.get('type', 'Unknown')}")
                    val = s.get("value", "N/A")
                    if len(val) > 60:
                        val = val[:60] + "..."
                    print(f"            Value : {val}")
                    print()
        else:
            print_error("No JS files found on homepage")

    if not args.no_brute:
        print_section("PHASE 3 — WAF DETECTION & BRUTE-FORCE")

        print_info("Detecting WAF...")
        waf = detect_waf(target_url, args.timeout, headers, aggressive=args.waf_aggressive)

        if waf["waf_detected"]:
            print_warn(f"WAF Detected: {waf['waf_name']}")
            if waf.get("recommendation"):
                print_warn(f"Recommendation: {waf['recommendation']}")
            print()
        else:
            print_success("No WAF detected")

        print_info("Establishing Soft-404 baseline (3 probes)...")
        baseline = get_soft_404_baseline(target_url, args.timeout, headers)
        if baseline["status"] == 200:
            print_warn(f"Soft-404 Detected: Target returns 200 OK for non-existent paths (Avg Length: {baseline['length']})")
        else:
            print_success(f"Normal 404 behavior detected (Status: {baseline['status']})")

        wl_path = args.wordlist if args.wordlist else get_default_wordlist()

        if not os.path.exists(wl_path):
            print_error(f"Wordlist not found: {wl_path}")
        else:
            print_info(f"Loading wordlist: {os.path.basename(wl_path)}")
            wl_paths = load_wordlist(wl_path)
            original_count = len(wl_paths)

            # Remove paths already discovered in Phases 1 & 2
            wl_paths = [p for p in wl_paths if p not in discovered_paths]
            removed = original_count - len(wl_paths)
            if removed:
                print_info(f"Skipped {removed} already-discovered paths (no duplicates)")

            # Resume: skip already-checked paths
            if resumed_paths:
                before = len(wl_paths)
                wl_paths = [p for p in wl_paths if p not in resumed_paths]
                skipped = before - len(wl_paths)
                if skipped:
                    print_info(f"Resume: skipped {skipped} previously-checked paths")

            print_info(f"Bruteforcing {len(wl_paths)} paths with {args.threads} threads...")
            print()

            _progress_count = [0]
            _brute_checked = set(resumed_paths)

            try:
                brute_results = bruteforce(
                    target_url,
                    wl_paths,
                    threads=args.threads,
                    timeout=args.timeout,
                    headers=headers,
                    delay=args.delay,
                    allowed_status_codes=allowed_codes,
                    baseline=baseline,
                )
            except KeyboardInterrupt:
                print_warn("Brute-force interrupted — saving progress...")
                _brute_checked.update(wl_paths)  # Mark all as checked
                save_progress(list(_brute_checked), all_results, args.output, target_url)
                print_success(f"Progress saved to {args.output}.progress.json")
                raise

            print()
            print_success(f"Bruteforce complete — {len(brute_results)} endpoints found")

            for r in brute_results:
                if r["path"] not in discovered_paths:
                    discovered_paths.add(r["path"])
                    all_results.append(r)

            if args.version_fuzz and brute_results:
                print()
                print_info("Version fuzzing discovered paths...")
                found_paths = [r["path"] for r in brute_results]
                versioned = generate_versioned_paths(found_paths)

                if versioned:
                    # Remove already discovered
                    versioned = [p for p in versioned if p not in discovered_paths]
                    if versioned:
                        print_info(f"Testing {len(versioned)} version variants...")

                        version_results = bruteforce(
                            target_url,
                            versioned,
                            threads=args.threads,
                            timeout=args.timeout,
                            headers=headers,
                            delay=args.delay,
                            allowed_status_codes=allowed_codes,
                            baseline=baseline,
                        )

                        version_count = 0
                        for r in version_results:
                            if r["path"] not in discovered_paths:
                                discovered_paths.add(r["path"])
                                r["source"] = "version_fuzz"
                                all_results.append(r)
                                version_count += 1

                        print_success(f"Version fuzzing found {version_count} additional endpoints")
                    else:
                        print_info("No new version variants to test")
                else:
                    print_info("No versioned paths detected for fuzzing")

    unverified = [r for r in all_results if r.get("status") == "N/A"]

    if unverified:
        print_section("PHASE 4 — VERIFYING DISCOVERED PATHS")
        print_info(f"Verifying {len(unverified)} paths from crawler / JS scan...")

        if baseline is None:
            baseline = get_soft_404_baseline(target_url, args.timeout, headers)

        verified_count = 0

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(_verify_path, target_url, r, args.timeout, headers, allowed_codes, baseline) for r in unverified]
            for future in as_completed(futures):
                if future.result():
                    verified_count += 1

        print_success(f"Verified — {verified_count} paths returned allowed status codes")

    # Filter to only allowed status codes
    all_results = [r for r in all_results if isinstance(r.get("status"), int) and r["status"] in allowed_codes]

    # De-duplicate by path
    seen_paths = set()
    unique_results = []
    for r in all_results:
        if r["path"] not in seen_paths:
            seen_paths.add(r["path"])
            unique_results.append(r)
    all_results = unique_results

    endpoints_200 = [r for r in all_results if r.get("status") == 200]

    if endpoints_200 and HAS_CORS_SCANNER:
        print_section("PHASE 5 — CORS MISCONFIGURATION SCAN")
        print_info(f"Checking {len(endpoints_200)} endpoints for CORS misconfigurations...")

        cors_urls = [r.get("url", build_url(target_url, r.get("path", ""))) for r in endpoints_200]
        cors_findings = scan_cors_bulk(cors_urls, threads=args.threads, timeout=args.timeout, headers=headers)

        if cors_findings:
            for cf in cors_findings:
                sev = cf.get("severity", "MEDIUM")
                url_short = cf.get("url", "?").split("/", 3)[-1] if "/" in cf.get("url", "") else cf.get("url", "?")
                desc = cf.get("description", "")
                if sev == "CRITICAL":
                    print_error(f"[CORS-CRITICAL] {url_short}")
                    print_error(f"  {desc}")
                elif sev == "HIGH":
                    print_warn(f"[CORS-HIGH] {url_short}")
                    print_warn(f"  {desc}")
                else:
                    print_info(f"[CORS-{sev}] {url_short} — {desc}")
            print()
            print_success(f"CORS scan complete — {len(cors_findings)} misconfigurations found")
        else:
            print_success("No CORS misconfigurations detected")

    elif endpoints_200 and not HAS_CORS_SCANNER:
        print_warn("CORS scanner module not available — skipping Phase 5")

    print_section("SEVERITY SCORING & RESULTS")

    # Score every result
    scored = [score_endpoint(r) for r in all_results]
    scored = sort_by_severity(scored)
    stats = get_severity_stats(scored)

    # Summary table
    print_severity_summary(stats)

    # Determine which severity levels to show in detail
    if args.show_all:
        detail_sevs = list(SEVERITY_ORDER)
    else:
        try:
            cutoff = SEVERITY_ORDER.index(args.min_severity) + 1
        except ValueError:
            cutoff = 2  # default HIGH
        detail_sevs = SEVERITY_ORDER[:cutoff]

    summary_sevs = [s for s in SEVERITY_ORDER if s not in detail_sevs]

    # Detailed output for selected severities
    for sev in detail_sevs:
        sev_results = [r for r in scored if r.get("severity") == sev]
        if sev_results:
            print_severity_group(sev, sev_results)

    # Count-only output for remaining severities
    for sev in summary_sevs:
        count = stats.get(sev, 0)
        if count > 0:
            print_info(f"[{sev}] {count} endpoints found — use --show-all to see details")

    interesting = [
        r for r in scored
        if r.get("status") == 200 and r.get("severity") in ("CRITICAL", "HIGH")
    ][:3]

    if interesting:
        print_section("HTTP METHOD TESTING — TOP ENDPOINTS")

        for r in interesting:
            url = r.get("url", build_url(target_url, r.get("path", "")))
            print_info(f"Testing methods on {r.get('path', url)} ...")

            methods = test_http_methods(url, args.timeout, headers)
            if methods:
                for method, status in methods.items():
                    if method in ("DELETE", "PUT") and status in (200, 201, 204):
                        print_warn(f"  DANGEROUS: {method} {r.get('path', '')} returns {status}!")
                    elif status in (200, 201, 204):
                        print_success(f"  {method}: {status}")
                    elif status in (403, 405):
                        print_info(f"  {method}: {status}")
                    else:
                        print_found(f"  {method}", status)
            print()

    if all_secrets and HAS_JWT_TESTER:
        jwt_tokens = extract_jwts_from_results(all_secrets)

        if jwt_tokens:
            print_section("JWT VULNERABILITY TESTING")
            print_info(f"Found {len(jwt_tokens)} JWT token(s) — testing for vulnerabilities...")

            for i, token in enumerate(jwt_tokens[:5], 1):  # Limit to first 5
                token_short = token[:30] + "..." if len(token) > 30 else token
                print_info(f"Token #{i}: {token_short}")

                # Test none algorithm
                test_url = target_url.rstrip("/") + "/api/v1/me"  # Common endpoint
                none_vuln = test_jwt_none_algorithm(token, test_url, headers, args.timeout)
                if none_vuln:
                    print_error(f"  [CRITICAL] Algorithm 'none' bypass ACCEPTED!")
                    jwt_findings.append(f"[CRITICAL] Token #{i} — 'none' algorithm bypass accepted at {test_url}")
                else:
                    print_success(f"  Algorithm 'none' bypass: rejected (safe)")

                # Test weak secrets
                weak = test_jwt_weak_secret(token)
                if weak:
                    print_error(f"  [CRITICAL] Weak signing secret found: '{weak}'")
                    jwt_findings.append(f"[CRITICAL] Token #{i} — signed with weak secret: '{weak}'")
                else:
                    print_success(f"  Weak secret test: no common weak secret found (safe)")

                print()

            if jwt_findings:
                print_warn(f"JWT testing complete — {len(jwt_findings)} vulnerabilities found!")
            else:
                print_success("JWT testing complete — no vulnerabilities found")
    elif all_secrets and not HAS_JWT_TESTER:
        jwt_tokens_check = [s for s in all_secrets if "jwt" in s.get("type", "").lower() or "bearer" in s.get("type", "").lower()]
        if jwt_tokens_check:
            print_warn("JWT tokens found but jwt_tester module not available — install PyJWT for JWT testing")


    elapsed = time.time() - start_time

    print_section("SCAN COMPLETE")

    # Quick list of all found endpoints
    if scored:
        border = "═" * 56
        print(f"  {border}")
        print(f"    FINAL DISCOVERED ENDPOINTS")
        print(f"  {border}")
        for r in scored:
            sev = r.get("severity", "INFO")
            status = r.get("status", "?")
            path = r.get("path", "?")
            source = r.get("source", "")
            print_found(f"{path}  <- {source}", status, "")
        print(f"  {border}")
        print()

    print_success(f"Total endpoints found : {stats.get('total', 0)}")
    print_success(f"Secrets found         : {len(all_secrets)}")
    if cors_findings:
        print_success(f"CORS findings         : {len(cors_findings)}")
    if jwt_findings:
        print_success(f"JWT vulnerabilities   : {len(jwt_findings)}")
    print_info(f"Scan duration         : {elapsed:.1f} seconds")
    print()

    # Save reports
    try:
        txt_file, json_file, md_file = save_report(
            scored, all_secrets, target_url, args.output, stats, elapsed,
            cors_findings=cors_findings, jwt_findings=jwt_findings,
        )
        print_success(f"Text report saved     : {txt_file}")
        print_success(f"JSON report saved     : {json_file}")
        print_success(f"Markdown report saved : {md_file}")
    except Exception as e:
        print_error(f"Failed to save report: {e}")

    # Clean up progress file on successful completion
    delete_progress(args.output)

    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        print_error("Scan interrupted by user.")
        sys.exit(1)
