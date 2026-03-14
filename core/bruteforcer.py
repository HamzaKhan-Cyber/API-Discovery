import re
import sys
import time
import random
import threading
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

try:
    from difflib import SequenceMatcher
except ImportError:
    SequenceMatcher = None

from core.display import print_progress, print_warn, print_info


class RateLimitDetector:
    WINDOW_SIZE = 20
    PAUSE_THRESHOLD_429 = 3
    SUSPECT_THRESHOLD_403 = 10

    def __init__(self, base_delay=0):
        self._window = deque(maxlen=self.WINDOW_SIZE)
        self._lock = threading.Lock()
        self._current_delay = base_delay
        self._paused = False

    def record(self, status_code):
        with self._lock:
            self._window.append(status_code)

            count_429 = self._window.count(429)
            count_403 = self._window.count(403)

            if count_429 >= self.PAUSE_THRESHOLD_429 and not self._paused:
                self._paused = True
                return "pause"


            if not self._paused and count_403 >= self.SUSPECT_THRESHOLD_403:
                new_delay = max(self._current_delay * 2, 1.0)
                if new_delay != self._current_delay:
                    self._current_delay = new_delay
                    return new_delay

        return None

    def clear_pause(self):
        with self._lock:
            self._paused = False
            self._window.clear()

    @property
    def current_delay(self):
        with self._lock:
            return self._current_delay


def load_wordlist(wordlist_path):
    paths = []
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if not line.startswith("/"):
                    line = "/" + line
                paths.append(line)
    except FileNotFoundError:
        pass
    except Exception:
        pass

    seen = set()
    unique = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    return unique


def get_soft_404_baseline(base_url, timeout=5, headers=None):
    statuses = []
    lengths = []
    word_counts = []
    body_sample = ""

    for _ in range(3):
        random_str = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))
        fake_path = f"/not-found-xyz-{random_str}"
        url = base_url.rstrip("/") + fake_path

        try:
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
            statuses.append(resp.status_code)
            lengths.append(len(resp.content))
            word_counts.append(len(resp.text.split()))
            if not body_sample:
                body_sample = resp.text[:500]
        except Exception:
            statuses.append(404)
            lengths.append(0)
            word_counts.append(0)

    most_common_status = Counter(statuses).most_common(1)[0][0] if statuses else 404

    avg_length = int(sum(lengths) / len(lengths)) if lengths else 0
    avg_words = int(sum(word_counts) / len(word_counts)) if word_counts else 0

    baseline = {
        "status": most_common_status,
        "length": avg_length,
        "words": avg_words,
        "body_sample": body_sample,
    }
    return baseline


def check_path(base_url, path, timeout=5, headers=None, delay=0, baseline=None):
    url = base_url.rstrip("/") + path
    result = {
        "path": path,
        "url": url,
        "status": 0,
        "length": 0,
        "redirect": None,
        "source": "bruteforce",
    }

    if delay > 0:
        jitter = random.uniform(delay * 0.5, delay * 1.5)
        time.sleep(jitter)

    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        result["status"] = resp.status_code
        result["length"] = len(resp.content)

        if resp.status_code in (301, 302, 303, 307, 308):
            result["redirect"] = resp.headers.get("Location", None)

        if baseline and result["status"] == 200 and baseline["status"] == 200:
            bl_len = baseline["length"]
            bl_words = baseline["words"]
            resp_words = len(resp.text.split())

            is_soft_404 = False

            if SequenceMatcher and baseline.get("body_sample"):
                ratio = SequenceMatcher(
                    None, resp.text[:500], baseline["body_sample"]
                ).ratio()
                if ratio > 0.85:
                    is_soft_404 = True

            if not is_soft_404 and bl_len > 0 and bl_words > 0:
                len_match = abs(result["length"] - bl_len) <= bl_len * 0.15
                word_match = abs(resp_words - bl_words) <= bl_words * 0.15
                if len_match and word_match:
                    is_soft_404 = True

            if is_soft_404:
                result["status"] = 0

    except requests.exceptions.Timeout:
        result["status"] = 0
    except requests.exceptions.ConnectionError:
        result["status"] = 0
    except Exception:
        result["status"] = 0

    return result


class _ProgressCounter:
    """Simple thread-safe counter for progress reporting."""
    def __init__(self):
        self.count = 0
        self._lock = threading.Lock()

    def increment(self):
        with self._lock:
            self.count += 1
            return self.count


def bruteforce(base_url, paths, threads=10, timeout=5, headers=None, delay=0,
               allowed_status_codes=None, baseline=None):
    if allowed_status_codes is None:
        allowed_status_codes = [200, 201, 301, 302, 403, 405, 500]

    if not paths:
        return []

    results = []
    total = len(paths)
    counter = _ProgressCounter()
    rate_detector = RateLimitDetector(base_delay=delay)

    def _worker(path):
        current_delay = rate_detector.current_delay
        r = check_path(base_url, path, timeout, headers, current_delay, baseline)
        current = counter.increment()

        suggestion = rate_detector.record(r["status"])
        if suggestion == "pause":
            print_warn("\n  [RATE LIMIT] 429 responses detected — pausing 30s...")
            time.sleep(30)
            rate_detector.clear_pause()
            print_info("  Resuming scan...")
        elif isinstance(suggestion, (int, float)):
            print_warn(f"\n  [RATE LIMIT] Suspicious 403 pattern — delay increased to {suggestion:.1f}s")

        if current % 5 == 0 or current == total:
            print_progress(current, total, prefix="Bruteforcing")
        return r

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_worker, p): p for p in paths}
        try:
            for future in as_completed(futures):
                try:
                    r = future.result()
                    if r["status"] in allowed_status_codes:
                        results.append(r)
                except Exception:
                    pass
        except KeyboardInterrupt:
            sys.stdout.write("\n")
            executor.shutdown(wait=False, cancel_futures=True)
            print_progress(total, total, prefix="Bruteforcing")
            raise

    print_progress(total, total, prefix="Bruteforcing")

    return results


WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server": ["cloudflare"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-id-2"],
        "server": ["amazons3", "awselb", "cloudfront"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-origin-hop"],
        "server": ["akamai", "akamaighost"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["incapsula"],
    },
    "F5 BIG-IP": {
        "headers": ["x-wa-info"],
        "server": ["big-ip", "bigip", "f5"],
    },
    "ModSecurity": {
        "headers": [],
        "server": ["mod_security", "modsecurity"],
    },
    "Barracuda": {
        "headers": ["barra_counter_session"],
        "server": ["barracuda"],
    },
}


def detect_waf(base_url, timeout=5, headers=None, aggressive=False):
    result = {
        "waf_detected": False,
        "waf_name": None,
        "recommendation": None,
    }

    test_paths = ["/"]

    if aggressive:
        test_paths += [
            "/?id=1'%20OR%20'1'='1",
            "/<script>alert(1)</script>",
            "/../../../../etc/passwd",
        ]

    try:
        for test_path in test_paths:
            url = base_url.rstrip("/") + test_path
            try:
                resp = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
            except requests.exceptions.RequestException:
                continue

            resp_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            server_header = resp_headers.get("server", "").lower()

            for waf_name, sigs in WAF_SIGNATURES.items():
                for sig_header in sigs["headers"]:
                    if sig_header.lower() in resp_headers:
                        result["waf_detected"] = True
                        result["waf_name"] = waf_name
                        result["recommendation"] = f"Use --delay 2 to avoid rate limiting by {waf_name}"
                        return result

                for server_sig in sigs["server"]:
                    if server_sig in server_header:
                        result["waf_detected"] = True
                        result["waf_name"] = waf_name
                        result["recommendation"] = f"Use --delay 2 to avoid rate limiting by {waf_name}"
                        return result

            if resp.status_code == 403:
                body_lower = resp.text.lower()
                waf_keywords = [
                    "access denied", "forbidden", "blocked",
                    "security", "firewall", "waf", "captcha",
                    "challenge", "ray id", "attention required",
                ]
                for kw in waf_keywords:
                    if kw in body_lower:
                        result["waf_detected"] = True
                        result["waf_name"] = "Unknown WAF"
                        result["recommendation"] = "Use --delay 2 to avoid rate limiting"
                        return result

    except Exception:
        pass

    return result


def test_http_methods(url, timeout=5, headers=None):
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
    results = {}

    for method in methods:
        try:
            resp = requests.request(
                method,
                url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            results[method] = resp.status_code
        except requests.exceptions.Timeout:
            results[method] = 0
        except requests.exceptions.ConnectionError:
            results[method] = 0
        except Exception:
            results[method] = 0

    return results


_VERSION_RE = re.compile(r'/v(\d+(?:\.\d+)?)/')

VERSION_VARIANTS = [
    "v1", "v2", "v3", "v4", "v5",
    "v1.0", "v2.0", "v3.0",
    "latest", "beta", "alpha", "stable",
]


def generate_versioned_paths(found_paths):
    existing = set(found_paths)
    new_paths = set()

    for path in found_paths:
        match = _VERSION_RE.search(path)
        if match:
            original_version = match.group(0)
            for variant in VERSION_VARIANTS:
                new_path = path.replace(original_version, f"/{variant}/")
                if new_path not in existing:
                    new_paths.add(new_path)

    return sorted(new_paths)