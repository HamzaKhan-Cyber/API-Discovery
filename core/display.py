import sys
from colorama import init, Fore, Style

if hasattr(sys.stdout, 'reconfigure') and sys.stdout.encoding is not None and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

init(autoreset=True)

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
    if status_code in (200, 201, 204):
        color = GREEN
    elif status_code in (301, 302, 403, 405, 500):
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
    border = "═" * width
    padding = width - len(title) - 2
    print(f"\n  {CYAN}{BRIGHT}╔{border}╗{RESET}")
    print(f"  {CYAN}{BRIGHT}║  {WHITE}{title}{CYAN}{' ' * padding}║{RESET}")
    print(f"  {CYAN}{BRIGHT}╚{border}╝{RESET}\n")


def print_severity_summary(stats):
    """Print severity summary table with colored counts"""
    border = "═" * 42
    print(f"\n  {BRIGHT}╔{border}╗{RESET}")
    print(f"  {BRIGHT}║          SEVERITY SUMMARY                ║{RESET}")
    print(f"  {BRIGHT}╠{border}╣{RESET}")

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
        pad = max(1, 40 - 4 - len(label) - 2 - len(count_str))
        print(f"  {BRIGHT}║{RESET}  {color}{label}{RESET}{' ' * pad}{BRIGHT}{count_str}{RESET}  {BRIGHT}║{RESET}")

    total = stats.get("total", 0)
    total_str = str(total)
    tpad = max(1, 40 - 4 - 5 - 2 - len(total_str))
    print(f"  {BRIGHT}╠{border}╣{RESET}")
    print(f"  {BRIGHT}║  Total{' ' * tpad}{total_str}  ║{RESET}")
    print(f"  {BRIGHT}╚{border}╝{RESET}\n")


def print_severity_group(severity, results):
    """Print all results belonging to a particular severity group"""
    colors = {
        "CRITICAL": RED + BRIGHT,
        "HIGH": YELLOW + BRIGHT,
        "MEDIUM": CYAN,
        "LOW": GREEN,
        "INFO": WHITE,
    }
    color = colors.get(severity, WHITE)

    header = f" [{severity}] — {len(results)} endpoint(s) "
    dashes = "─" * max(50, len(header) + 4)
    print(f"\n  {color}{dashes}{RESET}")
    print(f"  {color}{header}{RESET}")
    print(f"  {color}{dashes}{RESET}")

    for r in results:
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


def print_progress(current, total, prefix="Bruteforcing"):
    """Print an in-place progress indicator"""
    bar_len = 30
    filled = int(bar_len * current / total) if total else 0
    bar = "█" * filled + "░" * (bar_len - filled)
    pct = int(100 * current / total) if total else 0
    sys.stdout.write(f"\r  {CYAN}[*]{RESET} {prefix}... |{bar}| {current}/{total} ({pct}%)")
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()