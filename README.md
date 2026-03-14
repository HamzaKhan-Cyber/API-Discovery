<div align="center">

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

# 🔍 API-Discovery

**Hidden API Endpoint Finder** — A multi-phase Python tool for discovering exposed API endpoints, secrets, and misconfigurations in web applications.

[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0-red?style=flat-square)](https://github.com/HamzaKhan-Cyber/API-Discovery)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgray?style=flat-square)](https://github.com/HamzaKhan-Cyber/API-Discovery)

</div>

---

## ⚠️ Disclaimer

> **This tool is intended for authorized security testing only.**
> Only use on systems you own or have **explicit written permission** to test.
> Unauthorized use is illegal. The author is not responsible for any misuse.

---

## ✨ Features

### 🔎 5-Phase Scanning Engine

| Phase | Description |
| --- | --- |
| **Phase 1** | `robots.txt` & `sitemap.xml` parsing — nested sitemap support |
| **Phase 2** | JavaScript file scanning — extracts API paths + 25+ secret types |
| **Phase 3** | WAF detection + soft-404 baseline + multi-threaded wordlist bruteforce (700+ paths) |
| **Phase 4** | Path verification with soft-404 filtering |
| **Phase 5** | CORS misconfiguration detection (CRITICAL / HIGH / MEDIUM) |

> **Post-scan:** Severity scoring, HTTP method testing on top endpoints, JWT vulnerability testing

### 🛡️ Smart Detection

- **Soft-404 detection** via `difflib.SequenceMatcher` — eliminates false positives
- **Sliding-window rate limit detector** — auto-pause on 429, auto-delay on 403 pattern
- **Jitter delay** — randomized timing (±50%) for WAF evasion
- **Authenticated scanning** — Bearer token, Basic auth, Cookie, Custom headers
- **WAF detection** — Cloudflare, AWS WAF, Akamai, Sucuri, F5, ModSecurity, Imperva

### 🔐 Secret Detection (25+ Types)

- AWS Access Keys, GitHub Tokens, Google OAuth, Stripe Keys
- JWT Tokens, Slack Webhooks, SendGrid, Mailgun, Twilio
- Database connection strings, Hardcoded passwords, Internal IPs, Firebase URLs

### 📊 Output Formats

- `report.txt` — Human-readable terminal report
- `report.json` — Machine-readable structured data
- `report.md` — Markdown report with severity tables + redacted secrets

---

## 📦 Installation

```bash
git clone https://github.com/HamzaKhan-Cyber/API-Discovery.git
cd API-Discovery
pip install -r requirements.txt
```

### Requirements

```
requests
beautifulsoup4
colorama
urllib3
lxml          # Recommended — accurate XML sitemap parsing
PyJWT         # Optional  — enables JWT vulnerability testing
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
  --version-fuzz \
  --waf-aggressive
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

### Severity Summary — OWASP Juice Shop

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

### Secrets Found

```
  [!] SECRET FOUND in main.js
            Type  : Google OAuth
            Value : 1005568560502-6hm16lef8oh46hr2d98vf2ohlnj4nfhq...

  [!] SECRET FOUND in main.js
            Type  : Generic Secret / Password
            Value : IamUsedForTesting
```

### CORS Findings

```
  [CORS-HIGH] rest/admin/application-configuration
    Wildcard (*) Access-Control-Allow-Origin — any site can read responses
```

### Critical Endpoints

```
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
| --- | --- |
| OWASP Juice Shop | 434 endpoints — 61 CRITICAL, 2 secrets, 31 CORS misconfigs |
| DVWA | ✅ Tested |
| HackTheBox Labs | ✅ Tested |

---

## 👤 Author

**Hamza Khan** — Cybersecurity Researcher

- 🐙 GitHub: [@HamzaKhan-Cyber](https://github.com/HamzaKhan-Cyber)
- 💼 LinkedIn: [hamza-khan-908590287](https://linkedin.com/in/hamza-khan-908590287)
- ✍️ Medium: [@Senapi_9](https://medium.com/@Senapi_9)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

*Built for authorized security testing and educational purposes only.*

⭐ **If this tool helped you, consider starring the repo!**

</div>
