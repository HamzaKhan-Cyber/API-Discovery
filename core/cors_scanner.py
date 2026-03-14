from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


CORS_CRITICAL = "CRITICAL"
CORS_HIGH = "HIGH"
CORS_MEDIUM = "MEDIUM"


def check_cors(url, timeout=5, headers=None):
    test_origin = "https://evil-hacker.com"
    null_origin = "null"

    req_headers = dict(headers) if headers else {}
    req_headers["Origin"] = test_origin

    finding = None

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

        if acao:
            credentials_allowed = acac == "true"

            if acao == test_origin and credentials_allowed:
                return {
                    "url": url,
                    "severity": CORS_CRITICAL,
                    "description": "Origin is reflected with credentials allowed — full CORS bypass",
                    "acao": acao,
                    "acac": acac,
                }

            if acao == "*":
                return {
                    "url": url,
                    "severity": CORS_HIGH,
                    "description": "Wildcard (*) Access-Control-Allow-Origin — any site can read responses",
                    "acao": acao,
                    "acac": acac,
                }

            if acao == test_origin and not credentials_allowed:
                finding = {
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

    try:
        null_headers = dict(headers) if headers else {}
        null_headers["Origin"] = null_origin

        resp2 = requests.get(
            url,
            headers=null_headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )

        acao2 = resp2.headers.get("Access-Control-Allow-Origin", "").strip()
        acac2 = resp2.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

        if acao2 == null_origin:
            credentials_allowed2 = acac2 == "true"
            severity = CORS_CRITICAL if credentials_allowed2 else CORS_HIGH
            return {
                "url": url,
                "severity": severity,
                "description": (
                    "Null origin trusted with credentials — sandboxed iframe CORS bypass"
                    if credentials_allowed2
                    else "Null origin trusted — sandboxed iframe can read responses"
                ),
                "acao": acao2,
                "acac": acac2,
            }
    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass

    return finding


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

    severity_order = {CORS_CRITICAL: 0, CORS_HIGH: 1, CORS_MEDIUM: 2}
    findings.sort(key=lambda f: severity_order.get(f.get("severity"), 99))

    return findings