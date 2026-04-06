# Permi

[![PyPI version](https://badge.fury.io/py/permi.svg)](https://pypi.org/project/permi/)
[![CI](https://github.com/Peternasarah/permi/actions/workflows/ci.yml/badge.svg)](https://github.com/Peternasarah/permi/actions/workflows/ci.yml)

**AI-powered vulnerability scanner for Nigerian developers and global SMBs.**

Permi scans live websites and source code for security vulnerabilities, then uses AI to filter out false positives — so you only see findings that actually matter.

Built in Nigeria. For Nigeria. Then for the world.

---

## Two scan modes

### `--url` — Live web scanning
Point Permi at any website. It crawls the pages, tests for SQL injection, XSS, and checks security headers on the running application.

```bash
permi scan --url https://yoursite.com
```

### `--path` — Static source code scanning
Point Permi at a local folder or GitHub repository. It reads your code files, matches vulnerability patterns, and flags issues before they ship.

```bash
permi scan --path ./myapp
permi scan --path https://github.com/user/repo
```

---

## What Permi detects

### Web scanning (`--url`)
- **SQL Injection** — error-based, boolean-based blind, time-based blind
- **Cross-Site Scripting (XSS)** — reflected XSS with context-aware testing
- **Missing Security Headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **Server Information Disclosure** — Server and X-Powered-By header leakage

### Source code scanning (`--path`)
- **SQL Injection** — string concatenation, f-strings, % formatting in queries
- **Cross-Site Scripting** — innerHTML, document.write, Jinja2 |safe filter
- **Hardcoded Secrets** — passwords, API keys, AWS keys, Paystack/Flutterwave secrets
- **Insecure Practices** — eval(), exec(), pickle.loads(), SSL verification disabled, debug mode
- **USSD Vulnerabilities** — unvalidated sessionId, phoneNumber, serviceCode (Nigerian-specific)

---

## Installation

```bash
pip install permi
```

Requires Python 3.9+. Works on Windows, macOS, and Linux.

---

## Usage

**Scan a live website:**
```bash
permi scan --url https://yoursite.com
```

**Scan a local project:**
```bash
permi scan --path ./myapp
```

**Scan a GitHub repository:**
```bash
permi scan --path https://github.com/user/repo
```

**Show only high severity findings:**
```bash
permi scan --url https://yoursite.com --severity high
```

**Export results as JSON:**
```bash
permi scan --url https://yoursite.com --output json
```

**Skip AI filter (offline mode, path scan only):**
```bash
permi scan --path ./myapp --offline
```

**Limit pages crawled (web scan):**
```bash
permi scan --url https://yoursite.com --max-pages 50
```

---

## Setup — AI false positive filter

Permi uses [OpenRouter](https://openrouter.ai) to filter false positives with AI.
Create a free account, generate an API key, and add it to a `.env` file:

```
OPENROUTER_API_KEY=sk-or-your-key-here
```

No API key? Use `--offline` to skip AI filtering. All raw findings are shown.

---

## Example output — web scan

```
  ██████╗ ███████╗██████╗ ███╗   ███╗██╗
  ██╔══██╗██╔════╝██╔══██╗████╗ ████║██║
  ██████╔╝█████╗  ██████╔╝██╔████╔██║██║
  ██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╔╝██║██║
  ██║     ███████╗██║  ██║██║ ╚═╝ ██║██║
  ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝

  AI-Powered Vulnerability Scanner
  Built in Nigeria. For Nigeria. Then for the World.

[Permi] Mode     : Web scan (active HTTP testing)
[Permi] Target   : https://testsite.com
[Permi] Crawl    : up to 30 pages

[Permi] Engine found 4 raw finding(s)

[Permi] Running AI filter on 4 finding(s)...

  [1/4] WEB_SQL001 line 0 — REAL  SQL error returned when quote injected into 'id' parameter.
  [2/4] WEB_XSS001 line 0 — REAL  Payload reflected unencoded into HTML response.
  [3/4] WEB_HDR001 line 0 — REAL  Missing HSTS, CSP, and X-Frame-Options headers.
  [4/4] WEB_HDR002 line 0 — FP    Server header present but version not disclosed.

[Permi] Filter complete — 3 real  |  1 false positive(s) removed

────────────────────────────────────────────────────────────────────────
  [1] [HIGH] WEB_SQL001  SQL Injection — Error-based

  URL      : https://testsite.com/search
  Parameter: id
  Payload  : '
  Evidence : DB error: you have an error in your sql syntax
  Why      : Unsanitised input passed directly to a database query.
  AI       : REAL  SQL syntax error confirms user input reaches the query unescaped.

════════════════════════════════════════════════════════════════════════
  SCAN SUMMARY
════════════════════════════════════════════════════════════════════════
  Total findings  : 3  (filtered 1 false positive(s))
  High    : 2
  Medium  : 1
  Low     : 0
════════════════════════════════════════════════════════════════════════
```

---

## Nigerian-specific rules

Permi includes vulnerability rules built specifically for the Nigerian development context — USSD gateway misconfigurations, Paystack and Flutterwave credential exposure, and NDPR-relevant checks. No foreign scanner understands this market the way Permi does.

---

## Built by

Nasarah Peter Dashe — Cybersecurity student, University of Jos, Nigeria.

*Built in Nigeria. For Nigeria. Then for the World.*

---

## Links

- **Website:** [peternasarah.github.io/permi](https://peternasarah.github.io/permi)
- **PyPI:** [pypi.org/project/permi](https://pypi.org/project/permi)
- **Issues:** [github.com/Peternasarah/permi/issues](https://github.com/Peternasarah/permi/issues)
- **Security:** [SECURITY.md](SECURITY.md)
- **License:** [LICENSE](LICENSE)
