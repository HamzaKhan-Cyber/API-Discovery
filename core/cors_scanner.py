#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


CORS_CRITICAL = "CRITICAL"
CORS_HIGH = "HIGH"
CORS_MEDIUM = "MEDIUM"


def check_cors(url, timeout=5, headers=None):
    test_origin = "https://evil-hacker.com"

    req_headers = dict(headers) if headers else {}
    req_headers["Origin"] = test_origin

    try:
        resp = requests.get(
            url,
            headers=req_headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )

        acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

        if not acao:
            return None

        credentials_allowed = acac == "true"

        # CRITICAL: Origin reflected AND credentials allowed
        if acao == test_origin and credentials_allowed:
            return {
                "url": url,
                "severity": CORS_CRITICAL,
                "description": "Origin is reflected with credentials allowed — full CORS bypass",
                "acao": acao,
                "acac": acac,
            }

        # HIGH: Wildcard origin (*)
        if acao == "*":
            return {
                "url": url,
                "severity": CORS_HIGH,
                "description": "Wildcard (*) Access-Control-Allow-Origin — any site can read responses",
                "acao": acao,
                "acac": acac,
            }

        # MEDIUM: Origin reflected but no credentials
        if acao == test_origin and not credentials_allowed:
            return {
                "url": url,
                "severity": CORS_MEDIUM,
                "description": "Origin is reflected without credentials — partial CORS misconfiguration",
                "acao": acao,
                "acac": acac,
            }

    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass

    return None


def scan_cors_bulk(urls, threads=10, timeout=5, headers=None):
    findings = []

    if not urls:
        return findings

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_cors, url, timeout, headers): url
            for url in urls
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    findings.append(result)
            except Exception:
                pass

    # Sort by severity (CRITICAL first)
    severity_order = {CORS_CRITICAL: 0, CORS_HIGH: 1, CORS_MEDIUM: 2}
    findings.sort(key=lambda f: severity_order.get(f.get("severity"), 99))

    return findings
