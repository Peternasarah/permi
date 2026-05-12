<p align="center">
  <img src="logo.png" alt="Permi" width="600"/>
</p>

# Permi

**AI-Powered Vulnerability Scanner for Nigerian Developers**

[![PyPI version](https://badge.fury.io/py/permi.svg)](https://badge.fury.io/py/permi)
[![Downloads](https://pepy.tech/badge/permi)](https://pepy.tech/project/permi)
[![CI](https://github.com/Peternasarah/permi/actions/workflows/ci.yml/badge.svg)](https://github.com/Peternasarah/permi/actions/workflows/ci.yml)
[![License: PERMI COMMUNITY LICENSE](https://img.shields.io/badge/License-PCL-green.svg)](LICENSE)
[![Built in Nigeria](https://img.shields.io/badge/Built%20in-Nigeria%20🇳🇬-008751)](https://github.com/Peternasarah/permi)

---

## What is Permi?

Permi is an AI-powered security scanner that finds real vulnerabilities in web applications and source code — and filters out the false positives that waste your time.

Traditional scanners flag hundreds of issues. Most are noise. Permi uses an AI filter to confirm which findings are real before showing them to you, so you spend time fixing vulnerabilities, not chasing ghosts.

Built from Jos, Nigeria. For Nigerian developers. Then for the world.

---

## Quick Start

```bash
pip install permi
permi scan --url https://yoursite.com
```

---

## ⚠️ Windows Users — If Permi Freezes on First Run

Some Windows machines freeze immediately when running `permi` — even before the banner appears. This is caused by **Windows Defender or corporate antivirus** scanning Python processes in real time.

**Fix — add Permi to your antivirus exclusions:**

1. Open **Windows Security** → **Virus & threat protection** → **Manage settings**
2. Scroll to **Exclusions** → **Add an exclusion** → **Folder**
3. Add these two folders:
   - `C:\Users\<yourname>\.permi`
   - `C:\Users\<yourname>\Permi\venv` (or wherever your venv lives)
4. Open a new terminal and run `permi` again

If you are on a **corporate machine or university network**, your IT department may have group policies that block Python subprocess calls. In that case, run Permi from Windows Subsystem for Linux (WSL) instead:

```bash
wsl
pip install permi
permi scan --path ./myapp
```

---

## Installation

```bash
pip install permi
```

Requires Python 3.9+. Works on Windows, macOS, and Linux.

### For JavaScript/SPA scanning (React, Vue, Angular, Next.js)

```bash
pip install playwright
playwright install chromium
```

> **Note for low-RAM machines (4GB):** Use `--max-pages 10` with `--js` to keep memory usage manageable.

---

## Usage

### Scan a live website (standard HTTP)

```bash
permi scan --url https://yoursite.com
```

### Scan a JavaScript-rendered application (React / Vue / Angular / Next.js)

```bash
permi scan --url https://yoursite.com --js
```

The `--js` flag launches a headless Chromium browser that fully renders JavaScript before scanning. Required for single-page applications where links and forms are built dynamically.

Without `--js`, Permi will detect a SPA and show:

```
[Permi] ⚠️  JavaScript-rendered application detected.
[Permi]    Re-run with --js to scan the full JavaScript-rendered content:
[Permi]      permi scan --url https://yoursite.com --js
```

### Scan a local codebase

```bash
permi scan --path ./myapp
```

### Scan a GitHub repository

```bash
permi scan --path https://github.com/username/repo
```

### Include subdomains

```bash
permi scan --url https://yoursite.com --include-subdomains
```

### High severity findings only

```bash
permi scan --url https://yoursite.com --severity high
```

### Export results to a file

```bash
permi scan --url https://yoursite.com --export report.md
permi scan --path ./myapp --export results.json
permi scan --path ./myapp --export results.txt
```

### Show all raw findings (skip AI filter)

```bash
permi scan --url https://yoursite.com --offline
```

### JSON output (for CI/CD pipelines)

```bash
permi scan --url https://yoursite.com --output json
```

---

## Setting Up AI Filtering


###  Your own OpenRouter API key (unlimited)

```bash
permi setup --api-key YOUR_KEY
```

Get a free key at [openrouter.ai](https://openrouter.ai).

---

## GitHub Action — Scan Every Pull Request

Add Permi to your CI/CD pipeline so every pull request is automatically scanned. Findings are posted as a PR comment and the merge is blocked if high severity issues are found.

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  permi-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - uses: Peternasarah/permi-action@v1
        with:
          severity: high
          openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}
```

**What happens on every PR:**

- Permi scans the changed code
- AI filter removes false positives
- Findings posted as a PR comment
- Merge blocked if high severity issues found

**[→ View Permi GitHub Action on the Marketplace](https://github.com/marketplace/actions/permi-security-scanner)**

---

## How It Works

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│   Crawler   │───▶│    Scanner   │───▶│  AI Filter  │───▶│   Results    │
│ HTTP or JS  │    │ SQL · XSS    │    │ Real vs FP  │    │ Confirmed    │
│  (--js)     │    │ Headers · + │    │ 78% noise   │    │ findings     │
└─────────────┘    └──────────────┘    │ reduction   │    └──────────────┘
                                       └─────────────┘
```

**Two crawler modes:**
- **HTTP mode** (default) — fast BeautifulSoup crawler for server-rendered sites
- **JS mode** (`--js`) — Playwright headless Chromium for React/Vue/Angular SPAs

**AI filter features:**
- Confirms or dismisses each finding individually
- CSP-aware: knows when a reflected XSS cannot execute due to Content-Security-Policy
- Caches results to save API credits on repeated scans
- Three-tier verdict: REAL / REVIEW / FP with confidence score 0-100
- Community proxy for users without their own API key

---

## What Permi Detects

### Web scanning (`--url`)

| Category | What is detected |
|----------|-----------------|
| SQL Injection | Error-based, Boolean-based blind, Time-based blind |
| Cross-Site Scripting | Reflected XSS across all parameters |
| Missing Security Headers | CSP, HSTS, X-Frame-Options, Permissions-Policy |
| Server Information Disclosure | Server header, X-Powered-By version leakage |

### Source code scanning (`--path`)

| Category | What is detected |
|----------|-----------------|
| SQL Injection | String concatenation, f-strings, % formatting in queries |
| Cross-Site Scripting | innerHTML, document.write, Jinja2 \|safe filter |
| Hardcoded Secrets | Passwords, API keys, AWS keys, Paystack/Flutterwave secrets |
| Insecure Practices | eval(), exec(), pickle.loads(), SSL verification disabled, debug mode |
| USSD Vulnerabilities | Unvalidated sessionId, phoneNumber, serviceCode |

---

## Nigerian-Specific Rules

Permi includes rules built specifically for the Nigerian development context:

- **USSD gateway vulnerabilities** — unvalidated sessionId, phoneNumber, serviceCode
- **Paystack and Flutterwave key exposure** — detects Nigerian payment gateway secrets
- **NDPR-relevant patterns** — helps with Nigeria Data Protection Act compliance

No foreign scanner understands this market the way Permi does.

---

## Example Output

```
[Permi] Mode     : JS scan (Playwright headless browser)
[Permi] Target   : https://yourapp.com
[Permi] Crawl    : up to 30 pages (JS-rendered)

[Permi JS] Rendering page 1/30: https://yourapp.com
[Permi JS] Rendering page 2/30: https://yourapp.com/login
[Permi JS] Crawl complete — 8 pages rendered, 24 URLs found, 12 unique signatures

[Permi] Engine found 7 raw finding(s)
[Permi] Running AI filter on 7 finding(s)...

════════════════════════════════════════════════════════════════════════
  AI FILTER SUMMARY
════════════════════════════════════════════════════════════════════════
  Raw findings     : 7
  Confirmed real   : 4
  False positives  : 3 removed
  Noise reduced by : 43%  [████████░░░░░░░░░░░░]
  Avg confidence   : 89%

  Severity breakdown:
    ● High   : 2
    ● Medium : 2

  Top issues to fix:
    • 2× SQL Injection — string concatenation
    • 1× Hardcoded secret — generic password
    • 1× Insecure — SSL/TLS verification disabled
════════════════════════════════════════════════════════════════════════

  [1] [HIGH] WEB_SQL001  SQL Injection — Error-based
  URL       : https://yourapp.com/login
  Parameter : username
  Fix       : Use parameterised queries: cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
  AI        : REAL [94% confidence]  SQL syntax error confirms input reaches query unescaped.

  Scan completed in 2 min 14s | 12 URLs tested
```

---

## CLI Reference

```
permi scan --url URL             Scan a live website
  --js                           Use Playwright for JS-rendered SPAs
  --include-subdomains           Also scan subdomains
  --max-pages N                  Max pages to crawl (default: 30)
  --severity LEVEL               high | medium | low | all (default: all)
  --offline                      Skip AI filter, show raw findings
  --output FORMAT                human (default) | json
  --export FILE                  Export full report (.txt, .json, .md)

permi scan --path PATH           Scan local codebase or GitHub repo
  --severity LEVEL               Filter by severity
  --offline                      Skip AI filter
  --output FORMAT                human | json
  --export FILE                  Export full report

permi setup --api-key KEY        Use your own OpenRouter API key
permi info                       Show config, credits, Playwright status
permi feedback                   Share feedback with the Permi team
```

---

## CI/CD Integration

Permi exits with code `1` if any HIGH severity findings are confirmed. Use this in any pipeline:

```yaml
# GitHub Actions — inline (without the Marketplace Action)
- name: Run Permi security scan
  run: |
    pip install permi
    permi setup --api-key ${{ secrets.OPENROUTER_API_KEY }}
    permi scan --path . --severity high --output json --export permi-report.json
```

```bash
# Fail the build on high severity findings
permi scan --path ./myapp --severity high || exit 1
```

---

## Changelog

### v0.2.13 — JS/SPA Support + GitHub Action
- **NEW:** `--js` flag for JavaScript-rendered applications (React, Vue, Angular, Next.js, Nuxt)
- **NEW:** Playwright headless browser integration via `scanner/js_crawler.py`
- **NEW:** Network interception — discovers XHR/fetch API endpoints automatically
- **NEW:** Search box interaction — fills and submits search inputs to reveal parameterised URLs
- **NEW:** Clear SPA detection warning with exact `--js` command shown to user
- **NEW:** `permi info` now shows Playwright installation status
- **NEW:** [Permi GitHub Action](https://github.com/marketplace/actions/permi-security-scanner) — scan every PR automatically
- **NEW:** Windows antivirus freeze detection and guidance

### v0.2.13 — Accuracy & Speed
- **FIX:** CSP-aware XSS analysis — AI now correctly dismisses reflected XSS blocked by CSP
- **FIX:** Concurrent scanning — SQL and XSS run in parallel per URL via `asyncio.gather()` (~50% speed improvement)
- **FIX:** URL deduplication — same endpoint scanned only once
- **FIX:** Boolean SQL threshold raised; known redirect-page sizes filtered
- **FIX:** Time-based SQL reduced to MySQL SLEEP only; 10s hard cap; 6s threshold
- **NEW:** Scan timer — total scan duration shown in summary

### v0.2.2 — AI Filter + Community Proxy
- AI false-positive filter with 78% noise reduction
- Three-tier verdict: REAL / REVIEW / FP with 0-100 confidence score
- OpenRouter API key support with priority chain
- Fix templates — inline remediation per finding
- `--export` flag — save full reports as .txt, .json, or .md
- `--include-subdomains` flag for subdomain-aware web scanning
- Feedback system — `permi feedback` submits to Google Forms

### v0.1 — Foundation
- CLI scanner (web + static analysis)
- PyPI distribution (`pip install permi`)
- 17 detection rules across SQL, XSS, secrets, USSD, insecure practices
- SQLite database at `~/.permi/permi.db`

---

## Contributing

Pull requests welcome. Please open an issue first to discuss what you want to change.

If you find a vulnerability in a real Nigerian application using Permi, consider reporting it responsibly to the affected organisation before disclosing publicly.

---

## Author

**Nasarah Peter Dashe**
Founder · Cybersecurity Student @ University of Jos, Nigeria
[github.com/Peternasarah/permi](https://github.com/Peternasarah/permi) · [@peternasarah](https://twitter.com/peternasarah)

---

## Links

- **Website:** [peternasarah.github.io/permi](https://peternasarah.github.io/permi)
- **PyPI:** [pypi.org/project/permi](https://pypi.org/project/permi)
- **GitHub Action:** [github.com/marketplace/actions/permi-security-scanner](https://github.com/marketplace/actions/permi-security-scanner)
- **Issues:** [github.com/Peternasarah/permi/issues](https://github.com/Peternasarah/permi/issues)
- **Security:** [SECURITY.md](SECURITY.md)
- **License:** [LICENSE](LICENSE)

---

## License

PERMI COMMUNITY LICENSE — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <img src="logo.png" alt="Permi" width="400"/>
  <br/>
  <em>Built in Nigeria. For Nigeria. Then for the World.</em>
</p>
