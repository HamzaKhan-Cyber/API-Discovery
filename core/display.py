import sys
import os

from colorama import init, Fore, Style

# FIX #1: Use strip=True when output is not a terminal (piped to file)
# This prevents ANSI codes from appearing in redirected output
if hasattr(sys.stdout, 'reconfigure') and sys.stdout.encoding is not None and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

init(autoreset=True, strip=not sys.stdout.isatty())

RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
WHITE = Fore.WHITE
MAGENTA = Fore.MAGENTA
BRIGHT = Style.BRIGHT
RESET = Style.RESET_ALL


def show_banner():
    """Display ASCII art banner for API-Discovery"""
    banner = f"""{CYAN}{BRIGHT}
     _    ____ ___   ____  _
    / \\  |  _ \\_ _| |  _ \\(_)___  ___ _____   _____ _ __ _   _
   / _ \\ | |_) | |  | | | | / __|/ __/ _ \\ \\ / / _ \\ '__| | | |
  / ___ \\|  __/| |  | |_| | \\__ \\ (_| (_) \\ V /  __/ |  | |_| |
 /_/   \\_\\_|  |___| |____/|_|___/\\___\\___/ \\_/ \\___|_|   \\__, |
                                                          |___/
{WHITE}          Hidden API Endpoint Finder v2.0
{YELLOW}          For Authorized Testing Only
{RESET}"""
    print(banner)


def print_found(url, status_code, source=""):
    """Print found endpoint — Green=200, Yellow=403/301/302/500, Red=errors"""
    source_str = f" <- {source}" if source else ""
    if isinstance(status_code, int) and status_code in (200, 201, 204):
        color = GREEN
    elif isinstance(status_code, int) and status_code in (301, 302, 403, 405, 500):
        color = YELLOW
    else:
        color = RED
    print(f"  {color}{BRIGHT}[{status_code}]{RESET} {color}{url}{source_str}{RESET}")


def print_info(msg):
    """Print info message in cyan"""
    print(f"  {CYAN}[*]{RESET} {msg}")


def print_warn(msg):
    """Print warning message in yellow"""
    print(f"  {YELLOW}[!]{RESET} {YELLOW}{msg}{RESET}")


def print_error(msg):
    """Print error message in red"""
    print(f"  {RED}[-]{RESET} {RED}{msg}{RESET}")


def print_success(msg):
    """Print success message in green"""
    print(f"  {GREEN}[+]{RESET} {GREEN}{msg}{RESET}")


def print_section(title):
    """Print section header with decorative borders"""
    width = max(len(title) + 6, 56)
    border = "=" * width
    padding = width - len(title) - 2
    print(f"\n  {CYAN}{BRIGHT}+{border}+{RESET}")
    print(f"  {CYAN}{BRIGHT}|  {WHITE}{title}{CYAN}{' ' * padding}|{RESET}")
    print(f"  {CYAN}{BRIGHT}+{border}+{RESET}\n")


def print_severity_summary(stats):
    """Print severity summary table with colored counts"""
    # FIX #2: Dynamic width calculation based on actual content
    max_count_len = max(len(str(stats.get(s, 0))) for s in
                        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    max_count_len = max(max_count_len, len(str(stats.get("total", 0))))
    inner_width = max(42, 20 + max_count_len + 4)

    border = "=" * inner_width
    print(f"\n  {BRIGHT}+{border}+{RESET}")
    header = "SEVERITY SUMMARY"
    hpad = inner_width - len(header) - 2
    print(f"  {BRIGHT}| {header}{' ' * hpad} |{RESET}")
    print(f"  {BRIGHT}+{border}+{RESET}")

    colors = {
        "CRITICAL": RED + BRIGHT,
        "HIGH": YELLOW + BRIGHT,
        "MEDIUM": CYAN,
        "LOW": GREEN,
        "INFO": WHITE,
    }

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = stats.get(sev, 0)
        color = colors.get(sev, WHITE)
        label = f"[{sev}]"
        count_str = str(count)
        pad = max(1, inner_width - 4 - len(label) - 2 - len(count_str))
        print(f"  {BRIGHT}|{RESET}  {color}{label}{RESET}{' ' * pad}{BRIGHT}{count_str}{RESET}  {BRIGHT}|{RESET}")

    total = stats.get("total", 0)
    total_str = str(total)
    tpad = max(1, inner_width - 4 - 5 - 2 - len(total_str))
    print(f"  {BRIGHT}+{border}+{RESET}")
    print(f"  {BRIGHT}|  Total{' ' * tpad}{total_str}  |{RESET}")
    print(f"  {BRIGHT}+{border}+{RESET}\n")


def print_severity_group(severity, results, max_show=15):
    """Print results for a severity group, limited to max_show entries."""
    colors = {
        "CRITICAL": RED + BRIGHT,
        "HIGH": YELLOW + BRIGHT,
        "MEDIUM": CYAN,
        "LOW": GREEN,
        "INFO": WHITE,
    }
    color = colors.get(severity, WHITE)

    header = f" [{severity}] -- {len(results)} endpoint(s) "
    dashes = "-" * max(50, len(header) + 4)
    print(f"\n  {color}{dashes}{RESET}")
    print(f"  {color}{header}{RESET}")
    print(f"  {color}{dashes}{RESET}")

    shown = results[:max_show]
    remaining = len(results) - len(shown)

    for r in shown:
        path = r.get("path", r.get("url", "N/A"))
        status = r.get("status", "N/A")
        source = r.get("source", "unknown")
        reason = r.get("severity_reason", "")

        print(f"    {color}[{severity}]{RESET} {BRIGHT}{path}{RESET}")
        print(f"            Status : {status}")
        print(f"            Source : {source}")
        if reason:
            print(f"            Reason : {reason}")
        print()

    if remaining > 0:
        print(f"    {color}... and {remaining} more [{severity}] endpoints (see report files){RESET}")
        print()


# FIX #3: Thread-safe progress bar that won't garble with interleaved warnings
import threading
_progress_lock = threading.Lock()


def print_progress(current, total, prefix="Bruteforcing"):
    """Print an in-place progress indicator (thread-safe)"""
    with _progress_lock:
        bar_len = 30
        filled = int(bar_len * current / total) if total else 0
        bar = "#" * filled + "-" * (bar_len - filled)
        pct = int(100 * current / total) if total else 0
        line = f"\r  {CYAN}[*]{RESET} {prefix}... |{bar}| {current}/{total} ({pct}%)"
        sys.stdout.write(line)
        sys.stdout.flush()
        if current >= total:
            sys.stdout.write("\n")
            sys.stdout.flush()