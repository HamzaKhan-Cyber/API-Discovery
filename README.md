# 🔍 API-Discovery

> **Hidden API Endpoint Finder** — A multi-phase Python tool for discovering exposed API endpoints, secrets, and misconfigurations in web applications.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Version-2.0-red?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square)

```
     _    ____ ___   ____  _
    / \  |  _ \_ _| |  _ \(_)___  ___ _____   _____ _ __ _   _
   / _ \ | |_) | |  | | | | / __|/ __/ _ \ \ / / _ \ '__| | | |
  / ___ \|  __/| |  | |_| | \__ \ (_| (_) \ V /  __/ |  | |_| |
 /_/   \_\_|  |___| |____/|_|___/\___\___/ \_/ \___|_|   \__, |
                                                          |___/
          Hidden API Endpoint Finder v2.0
          For Authorized Testing Only
```


## ⚠️ Disclaimer

> **This tool is intended for authorized security testing only.**
> Only use on systems you own or have explicit written permission to test.
> Unauthorized use is illegal. The author is not responsible for any misuse.



## ✨ Features

### 🔎 9-Phase Scanning Engine
| Phase | Description |
|-------|-------------|
| **Phase 1** | `robots.txt` & `sitemap.xml` parsing — nested sitemap support |
| **Phase 2** | JavaScript file scanning — extracts API paths + 25+ secret types |
| **Phase 3** | WAF detection (Cloudflare, AWS, Akamai, Sucuri, F5, ModSecurity) |
| **Phase 4** | Multi-threaded wordlist bruteforce — 700+ built-in API paths |
| **Phase 5** | Path verification with soft-404 filtering |
| **Phase 6** | CORS misconfiguration detection (CRITICAL / HIGH / MEDIUM) |
| **Phase 7** | Severity scoring — CRITICAL / HIGH / MEDIUM / LOW / INFO |
| **Phase 8** | HTTP method testing (GET, POST, PUT, DELETE, PATCH, OPTIONS) |
| **Phase 9** | JWT vulnerability testing — `alg:none` bypass + weak secret cracking |

### 🛡️ Smart Detection
- **Soft-404 detection** via `difflib.SequenceMatcher` — eliminates false positives
- **Sliding-window rate limit detector** — auto-pause on 429, auto-delay on 403 pattern
- **Jitter delay** — randomized timing (±50%) for WAF evasion
- **Authenticated scanning** — Bearer token, Basic auth, Cookie, Custom headers

### 🔐 Secret Detection (25+ Types)
- AWS Access Keys, GitHub Tokens, Google OAuth, Stripe Keys
- JWT Tokens, Slack Webhooks, SendGrid, Mailgun, Twilio
- Database connection strings, Hardcoded passwords, Internal IPs

### 📊 Output Formats
- `report.txt` — Human-readable terminal report
- `report.json` — Machine-readable structured data
- `report.md` — Markdown report with severity tables



## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/HamzaKhan-Cyber/API-Discovery.git
cd API-Discovery

# Install dependencies
pip install -r requirements.txt
```

### Requirements
```
requests
beautifulsoup4
colorama
urllib3
PyJWT (optional — for JWT testing)
```

---

## 🚀 Usage

### Basic Scan
```bash
python api_discovery.py -u https://target.com
```

### Full Scan with All Options
```bash
python api_discovery.py -u https://target.com \
  -t 20 \
  --delay 1 \
  --show-all \
  --min-severity INFO \
  --version-fuzz
```

### Authenticated Scan
```bash
# Bearer Token
python api_discovery.py -u https://target.com \
  --auth-type bearer --auth-token YOUR_TOKEN

# Cookie-based
python api_discovery.py -u https://target.com \
  --cookie "session=abc123; csrf=xyz"

# Custom Header
python api_discovery.py -u https://target.com \
  --header "X-API-Key: your-key-here"
```

### Resume Interrupted Scan
```bash
python api_discovery.py -u https://target.com --resume
```

### Custom Wordlist
```bash
python api_discovery.py -u https://target.com \
  -w /path/to/wordlist.txt
```

---

## ⚙️ All Options

```
  -u, --url             Target base URL (e.g. https://example.com)
  -t, --threads         Concurrent threads (default: 10)
  -w, --wordlist        Custom wordlist path
  --timeout             Request timeout in seconds (default: 5)
  --delay               Delay between requests (default: 0)
  --show-all            Show all severity levels in detail
  --min-severity        Minimum severity to display (CRITICAL/HIGH/MEDIUM/LOW/INFO)
  --no-js               Skip JavaScript scanning
  --no-robots           Skip robots.txt / sitemap.xml
  --no-brute            Skip wordlist bruteforce
  --version-fuzz        Fuzz discovered paths with API version variants (v1-v5, beta, latest)
  --resume              Resume interrupted scan
  --auth-type           Auth type: bearer / basic / cookie / custom
  --auth-token          Auth credentials
  --cookie              Cookie header value
  --header              Custom header (repeatable)
  --waf-aggressive      Aggressive WAF detection with payloads
  -o, --output          Output filename without extension (default: api_discovery_report)
```

---

## 📸 Sample Output

### Scan Configuration
```
  ╔════════════════════════════════════════════════════════╗
  ║  SCAN CONFIGURATION                                    ║
  ╚════════════════════════════════════════════════════════╝
  [*] Target URL   : https://juice-shop.herokuapp.com
  [*] Threads      : 10
  [*] Timeout      : 5s
  [*] Status Codes : 200,201,301,302,403,405,500
```

### Secrets Found
```
  [!] SECRET FOUND in main.js
            Type  : Google OAuth
            Value : 1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq...

  [!] SECRET FOUND in main.js
            Type  : Generic Secret / Password
            Value : IamUsedForTesting
```

### Severity Summary (OWASP Juice Shop)
```
  ╔══════════════════════════════════════════╗
  ║          SEVERITY SUMMARY                ║
  ╠══════════════════════════════════════════╣
  ║  [CRITICAL]                          61  ║
  ║  [HIGH]                              58  ║
  ║  [MEDIUM]                            18  ║
  ║  [LOW]                              274  ║
  ║  [INFO]                              23  ║
  ╠══════════════════════════════════════════╣
  ║  Total                              434  ║
  ╚══════════════════════════════════════════╝
```

### CORS Findings
```
  [CORS-HIGH] rest/admin/application-configuration
    Wildcard (*) Access-Control-Allow-Origin — any site can read responses

  [CORS-HIGH] support/logs
    Wildcard (*) Access-Control-Allow-Origin — any site can read responses
```

### Critical Endpoints Found
```
  [CRITICAL] [200] /rest/admin/application-version
             Source: bruteforce
             Reason: Contains keyword: admin | Status 200: publicly accessible

  [CRITICAL] [200] /rest/admin/application-configuration
             Source: bruteforce
             Reason: Contains keyword: admin | Status 200: publicly accessible
```

---

## 🗂️ Project Structure

```
API-Discovery/
├── api_discovery.py        # Main entry point
├── requirements.txt        # Dependencies
├── wordlists/
│   └── api_paths.txt       # Built-in wordlist (700+ paths)
└── core/
    ├── bruteforcer.py      # Multi-threaded brute-force + WAF detection
    ├── cors_scanner.py     # CORS misconfiguration detection
    ├── crawler.py          # robots.txt, sitemap, JS discovery
    ├── display.py          # Colored terminal output
    ├── js_scanner.py       # JavaScript secret + path extraction
    ├── jwt_tester.py       # JWT vulnerability testing
    └── severity.py         # Endpoint severity scoring engine
```

---

## 🧪 Tested On

| Target | Findings |
|--------|----------|
| OWASP Juice Shop | 434 endpoints — 61 CRITICAL, 2 secrets, 31 CORS misconfigs |
| DVWA | ✅ Tested |
| HackTheBox Labs | ✅ Tested |

---

## 👤 Author

**Hamza Khan**
- GitHub: [@HamzaKhan-Cyber](https://github.com/HamzaKhan-Cyber)
- LinkedIn: [hamza-khan-908590287](https://linkedin.com/in/hamza-khan-908590287)
- Medium: [@Senapi_9](https://medium.com/@Senapi_9)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built for authorized security testing and educational purposes only.*