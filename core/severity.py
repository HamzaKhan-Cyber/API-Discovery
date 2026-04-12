import re


CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]


CRITICAL_KEYWORDS = [
    "password", "passwd", "token", "secret", "key", "credential",
    "private", "internal", "admin", "backup", "config", "auth",
    "jwt", "apikey", "api_key", "api-key", "access_key", "master",
    "root", "sudo", "superuser", "privilege", "ssh", "certificate",
    "encrypt", "decrypt", "credentials", "secrets",
    "shadow", "htpasswd", "authorize",
]

HIGH_KEYWORDS = [
    "export", "import", "ftp", "debug", "logs", "log", "restore",
    "billing", "upload", "download", "dump", "shell", "exec",
    "execute", "command", "cmd", "eval", "env", "environment",
    "console", "terminal", "deploy", "migration", "actuator",
    "heapdump", "threaddump", "trace", "profiler", "pprof",
    "phpinfo", "elmah", "server-status", "server-info",
    "swagger", "api-docs", "openapi", "graphiql",
]

MEDIUM_KEYWORDS = [
    "users", "user", "orders", "order", "payment", "checkout",
    "profile", "account", "register", "signup", "forgot", "reset",
    "search", "query", "graphql", "webhook", "sync",
    "subscription", "invoice", "cart", "basket", "transaction",
    "customer", "member", "people", "group", "role", "permission",
    "setting", "preference", "notification", "message", "email",
]

LOW_KEYWORDS = [
    "health", "ping", "status", "version", "info", "metrics",
    "robots", "sitemap", "manifest", "favicon", "crossdomain",
    "heartbeat", "ready", "alive", "liveness", "readiness",
    "docs", "doc", "documentation", "help", "about", "contact",
    "feed", "rss", "atom", "changelog",
]


KEYWORD_TIERS = [
    (CRITICAL, CRITICAL_KEYWORDS),
    (HIGH, HIGH_KEYWORDS),
    (MEDIUM, MEDIUM_KEYWORDS),
    (LOW, LOW_KEYWORDS),
]

# FIX #1: Pre-compile keyword patterns for better performance
# Original code ran 100+ regex compilations per endpoint — now compiled once
_COMPILED_PATTERNS = {}
for _tier_sev, _keywords in KEYWORD_TIERS:
    for _kw in _keywords:
        _pattern = re.compile(r'(?:^|[/\-_\.])' + re.escape(_kw) + r'(?:$|[/\-_\.])')
        _COMPILED_PATTERNS[(_tier_sev, _kw)] = _pattern


def _match_keywords(path_lower, keywords, tier_sev):
    """Check if any keyword matches in the path using pre-compiled patterns."""
    for kw in keywords:
        pattern = _COMPILED_PATTERNS.get((tier_sev, kw))
        if pattern and pattern.search(path_lower):
            return kw
    return None


def score_endpoint(result):
    """Score an endpoint's severity based on its path keywords and HTTP status."""
    path = result.get("path", "").lower()
    status = result.get("status", 0)
    reasons = []

    # Default severity
    severity = INFO

    # Check keyword tiers (highest severity first)
    for tier_sev, keywords in KEYWORD_TIERS:
        kw = _match_keywords(path, keywords, tier_sev)
        if kw:
            severity = tier_sev
            reasons.append(f"Contains keyword: {kw}")
            break

    # Adjust severity based on HTTP status code
    if isinstance(status, int):
        # FIX #2: Include 204 (No Content) as a success status alongside 200/201
        if status in (200, 201, 204):
            reasons.append(f"Status {status}: publicly accessible")
        elif status == 403:
            reasons.append("Status 403: exists but forbidden")
        elif status == 500:
            idx = SEVERITY_ORDER.index(severity)
            if idx > 0:
                severity = SEVERITY_ORDER[idx - 1]
            reasons.append("Status 500: server error — potential misconfiguration")
        elif status in (301, 302):
            reasons.append(f"Status {status}: redirect detected")
        elif status == 405:
            reasons.append("Status 405: method not allowed — endpoint exists")

    result["severity"] = severity
    result["severity_reason"] = " | ".join(reasons) if reasons else "No specific indicators"
    return result


def sort_by_severity(results):
    """Sort results by severity (CRITICAL first) then by status code (200 first)."""
    order_map = {s: i for i, s in enumerate(SEVERITY_ORDER)}

    def sort_key(r):
        sev_idx = order_map.get(r.get("severity", INFO), 999)
        status = r.get("status", 999)
        # FIX #3: Include 204 in the "good status" group for consistent sorting
        status_key = 0 if status in (200, 201, 204) else 1
        return (sev_idx, status_key, status)

    return sorted(results, key=sort_key)


def get_severity_stats(results):
    """Return a dict of counts per severity level + total."""
    stats = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        sev = r.get("severity", INFO)
        if sev in stats:
            stats[sev] += 1
        else:
            stats[INFO] += 1
    stats["total"] = len(results)
    return stats