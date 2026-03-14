#!/usr/bin/env python3
import re
from urllib.parse import urlparse

import requests



API_PATH_PATTERNS = [
    r'["\'](/api/[^\s"\'<>{}]+)["\']',
    r'["\'](/v[0-9]+/[^\s"\'<>{}]+)["\']',
    r'["\'](/rest/[^\s"\'<>{}]+)["\']',
    r'["\'](/graphql[^\s"\'<>{}]*)["\']',
    r'["\'](/internal/[^\s"\'<>{}]+)["\']',
    r'["\'](/admin/[^\s"\'<>{}]+)["\']',
    r'["\'](/auth/[^\s"\'<>{}]+)["\']',
    r'["\'](/oauth[^\s"\'<>{}]*)["\']',
    r'["\'](/webhook[^\s"\'<>{}]*)["\']',
    r'fetch\s*\(\s*["\']([^\s"\'<>{}]+)["\']',
    r'axios\s*\.\s*[a-z]+\s*\(\s*["\']([^\s"\'<>{}]+)["\']',
    r'\.get\s*\(\s*["\']([^\s"\'<>{}]+)["\']',
    r'\.post\s*\(\s*["\']([^\s"\'<>{}]+)["\']',
    r'\.put\s*\(\s*["\']([^\s"\'<>{}]+)["\']',
    r'\.delete\s*\(\s*["\']([^\s"\'<>{}]+)["\']',
    r'\.patch\s*\(\s*["\']([^\s"\'<>{}]+)["\']',
    r'\.request\s*\(\s*["\']([^\s"\'<>{}]+)["\']',
    r'baseURL\s*[=:]\s*["\']([^\s"\'<>{}]+)["\']',
    r'endpoint\s*[=:]\s*["\']([^\s"\'<>{}]+)["\']',
    r'apiUrl\s*[=:]\s*["\']([^\s"\'<>{}]+)["\']',
    r'apiBase\s*[=:]\s*["\']([^\s"\'<>{}]+)["\']',
    r'API_URL\s*[=:]\s*["\']([^\s"\'<>{}]+)["\']',
    r'API_BASE\s*[=:]\s*["\']([^\s"\'<>{}]+)["\']',
    r'API_ENDPOINT\s*[=:]\s*["\']([^\s"\'<>{}]+)["\']',
    r'url\s*:\s*["\'](/[^\s"\'<>{}]+)["\']',
    r'href\s*[=:]\s*["\'](/[^\s"\'<>{}]+)["\']',
    r'path\s*[=:]\s*["\'](/[^\s"\'<>{}]+)["\']',
    r'route\s*[=:]\s*["\'](/[^\s"\'<>{}]+)["\']',
    r'["\'](/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*)["\']',
]


SECRET_PATTERNS = {
    "AWS Access Key ID": r'\b(AKIA[0-9A-Z]{16})\b',
    "AWS Secret Access Key": r'(?i)(?:aws_secret|aws_secret_access_key|AWS_SECRET)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',
    "GitHub Personal Access Token": r'\b(gh[pousr]_[A-Za-z0-9_]{36})\b',
    "GitHub OAuth Access Token": r'\b(gho_[a-zA-Z0-9]{36})\b',
    "Google API Key": r'\b(AIza[0-9A-Za-z_\\-]{35})\b',
    "Google OAuth": r'\b([0-9]+-[a-z0-9_]+\.apps\.googleusercontent\.com)\b',
    "JWT Token": r'\b(ey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b',
    "Stripe Standard API Key": r'\b(sk_live_[0-9a-zA-Z]{24})\b',
    "Stripe Restricted API Key": r'\b(rk_live_[0-9a-zA-Z]{24})\b',
    "Stripe Publishable Key": r'\b(pk_live_[0-9a-zA-Z]{24})\b',
    "Slack Token": r'\b(xox[baprs]-[0-9]+-[0-9]+-[a-zA-Z0-9]+)\b',
    "Slack Webhook": r'(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)',
    "Twilio API Key": r'\b(SK[0-9a-fA-F]{32})\b',
    "Twilio Account SID": r'\b(AC[a-zA-Z0-9_\-]{32})\b',
    "SendGrid API Key": r'\b(SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43})\b',
    "Mailgun API Key": r'\b(key-[0-9a-zA-Z]{32})\b',
    "Heroku API Key": r'(?i)(?:heroku.{0,10}key|HEROKU_API_KEY)\s*[=:]\s*["\']([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["\']',
    "Square Access Token": r'\b(sq0atp-[0-9A-Za-z\-_]{22})\b',
    "Square OAuth Secret": r'\b(sq0csp-[0-9A-Za-z\-_]{43})\b',
    "RSA Private Key": r'(-----BEGIN(?:\sRSA|\sEC)?\sPRIVATE\sKEY-----)',
    "Generic Bearer Token": r'(?i)(?:bearer\s+)([A-Za-z0-9\-_.]+\.[A-Za-z0-9\-_.]+\.[A-Za-z0-9\-_]+)',
    "Database Connection String": r'((?:mysql|postgres|postgresql|mongodb|redis)(?:[+a-z0-9]*)://[a-zA-Z0-9_.:!?-]+@[a-zA-Z0-9_.-]+)',
    "Internal IP Address": r'\b((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}))\b',
    "Generic Secret / Password": r'(?i)(?:password|passwd|pwd|secret|api[-_]?key|apikey|api_token)\s*[=:]\s*["\']([^"\']{8,64})["\']',
    "Firebase Database": r'(https://[a-z0-9-]+\.firebaseio\.com)',
    "Firebase Configuration": r'(https://[a-z0-9-]+\.firebaseapp\.com)',
}


def extract_api_paths(js_content):
    found_paths = set()

    for pattern in API_PATH_PATTERNS:
        try:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                match = match.strip()
                if not match:
                    continue


                if match.startswith("/") or match.startswith("http"):

                    if match.startswith("http"):
                        parsed = urlparse(match)
                        path = parsed.path
                        if path and path != "/":
                            found_paths.add(path)
                    else:

                        path = match.split("?")[0].split("#")[0]
                        if path and len(path) > 1:
                            found_paths.add(path)
        except (re.error, ValueError, Exception):
            continue


    filtered = set()
    false_positives = {
        "/", "//", "/./", "/../",
        "/node_modules", "/webpack", "/src/", "/dist/",
        "/true", "/false", "/null", "/undefined",
    }
    bad_extensions = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                      ".css", ".scss", ".less", ".map", ".woff", ".woff2",
                      ".ttf", ".eot", ".mp4", ".mp3", ".pdf")

    for path in found_paths:
        if path in false_positives:
            continue
        if any(path.lower().endswith(ext) for ext in bad_extensions):
            continue
        if len(path) < 2 or len(path) > 200:
            continue
        filtered.add(path)

    return sorted(filtered)


def extract_secrets(js_content):
    found_secrets = []
    seen_values = set()

    for secret_type, pattern in SECRET_PATTERNS.items():
        try:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):

                value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                value = value.strip()

                if not value or value in seen_values:
                    continue


                if value.lower() in ("password", "secret", "key", "token", "api_key"):
                    continue
                if len(value) < 4:
                    continue

                seen_values.add(value)


                start = max(0, match.start() - 60)
                end = min(len(js_content), match.end() + 60)
                context = js_content[start:end].replace("\n", " ").strip()

                found_secrets.append({
                    "type": secret_type,
                    "value": value,
                    "context": context,
                })
        except (re.error, ValueError, Exception):
            continue

    return found_secrets


def scan_js_file(js_url, timeout=5, headers=None):
    """
    Download a JS file and run both path extraction and secret detection.
    Returns: {"url": js_url, "paths": [...], "secrets": [...]}
    """
    result = {
        "url": js_url,
        "paths": [],
        "secrets": [],
    }

    try:
        resp = requests.get(js_url, headers=headers, timeout=timeout, verify=False)
        if resp.status_code != 200:
            return result


        if len(resp.content) > 5 * 1024 * 1024:
            return result

        content = resp.content.decode("utf-8", errors="ignore")

        result["paths"] = extract_api_paths(content)
        result["secrets"] = extract_secrets(content)

    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass

    return result
