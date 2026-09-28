<p align="center">
  <img src="logo.png" alt="Permi" width="600"/>
</p>

# Permi

**The security signal filter for African fintech engineering teams**

[![PyPI version](https://badge.fury.io/py/permi.svg)](https://badge.fury.io/py/permi)
[![Downloads](https://pepy.tech/badge/permi)](https://pepy.tech/project/permi)
[![CI](https://github.com/Peternasarah/permi/actions/workflows/ci.yml/badge.svg)](https://github.com/Peternasarah/permi/actions/workflows/ci.yml)
[![License: PERMI COMMUNITY LICENSE](https://img.shields.io/badge/License-PCL-green.svg)](LICENSE)
[![Built in Nigeria](https://img.shields.io/badge/Built%20in-Nigeria%20🇳🇬-008751)](https://github.com/Peternasarah/permi)

---

## What is Permi?

Most security scanners produce hundreds of findings. Most are noise. Developers learn to ignore them — and that is when the real vulnerabilities get missed.

Permi fixes this. It scans your codebase for vulnerabilities, then uses an AI filter to confirm which findings are real before you see them. Your team spends time fixing actual problems instead of chasing false alarms.

Permi also includes rules built specifically for the African development context — USSD gateway vulnerabilities, Paystack and Flutterwave credential exposure, and patterns relevant to Nigeria Data Protection Act compliance. No foreign scanner prioritises this. Permi does.

Built from Jos, Nigeria. For African fintech engineering teams. Then for the world.

---

## Quick Start

```bash
pip install permi
permi setup --community    # 50 free AI filter credits — no card needed
permi scan ./myapp
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

If you are on a **corporate machine or university network**, your IT department may have group policies that block Python subprocess calls. Run Permi from Windows Subsystem for Linux (WSL) instead:

```bash
wsl
pip install permi
permi scan ./myapp
```

---

## Installation

```bash
pip install permi
```

Requires Python 3.9+. Works on Windows, macOS, and Linux.

---

## Usage

### Scan a local codebase

```bash
permi scan ./myapp
```

### Scan a GitHub repository

```bash
permi scan https://github.com/username/repo
```

### High severity findings only

```bash
permi scan ./myapp --severity high
```

### Export results to a file

```bash
permi scan ./myapp --export results.md
permi scan ./myapp --export results.json
permi scan ./myapp --export results.txt
permi scan ./myapp --export report.docx
```

If you give a bare filename (no folder), Permi saves it under `~/.permi/exports/` and prints that location so it's never a mystery where the file went. Give an absolute or relative path with a folder (`./reports/results.md`) to save it exactly there instead.

`.docx` exports are a curated summary — one example finding per category, meant for a compliance/sales handoff — so a full `.md` report with every finding is written alongside it automatically for technical review.

### Show all raw findings (skip AI filter)

```bash
permi scan ./myapp --offline
```

### JSON output (for CI/CD pipelines)

```bash
permi scan ./myapp --output json
```

---

## Setting Up AI Filtering

The AI filter is what separates confirmed vulnerabilities from noise. Without it, Permi shows all raw findings. With it, each finding is reviewed before you see it.

### Option 1 — Free community credits (recommended for new users)

```bash
permi setup --community
```

50 free AI filter calls. No credit card. Starts immediately.
The community proxy may take up to 60 seconds to wake on first use — it retries automatically.

### Option 2 — Your own OpenRouter API key (unlimited)

```bash
permi setup --api-key YOUR_KEY
```

Get a free key at [openrouter.ai](https://openrouter.ai).

---

## GitHub Action — Scan Every Pull Request

Add Permi to your CI/CD pipeline. Every pull request is automatically scanned, findings are posted as PR comments, and merges are blocked if high severity issues are found.

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
- Free forever

**[→ View Permi GitHub Action on the Marketplace](https://github.com/marketplace/actions/permi-security-scanner)**

---

## How It Works

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐
│    Scanner  │───▶│  AI Filter   │───▶│   Results    │
│ SQL · XSS   │    │ Confirms or  │    │ Only real    │
│ Secrets · + │    │ dismisses    │    │ findings     │
└─────────────┘    │ each finding │    └──────────────┘
                    └──────────────┘
```

**AI filter:**
- Reviews each finding individually before it reaches you
- CSP-aware: correctly dismisses reflected XSS when a Content-Security-Policy blocks execution
- Caches results so repeated scans do not consume extra credits
- Three-tier verdict: REAL / REVIEW / FP with confidence score 0-100
- Community proxy for users without their own API key

---

## What Permi Detects

### Source code scanning

| Category | What is detected |
|----------|-----------------|
| SQL Injection | String concatenation, f-strings, % formatting in queries |
| Cross-Site Scripting | innerHTML, document.write, Jinja2 \|safe filter |
| Hardcoded Secrets | Passwords, API keys, AWS keys, Paystack/Flutterwave secrets |
| Insecure Practices | eval(), exec(), pickle.loads(), SSL verification disabled, debug mode |
| USSD Vulnerabilities | Unvalidated sessionId, phoneNumber, serviceCode |

---

## Nigerian and African-Specific Rules

Permi includes rules built for the African development context that no global tool will ever prioritise:

- **USSD gateway vulnerabilities** — unvalidated sessionId, phoneNumber, serviceCode
- **Paystack and Flutterwave key exposure** — detects Nigerian payment gateway live secrets
- **BVN and NIN pattern detection** — NDPA-sensitive personal data in code
- **NDPA-relevant patterns** — helps with Nigeria Data Protection Act compliance

---

## Example Output

```
[Permi] Target   : ./myapp
[Permi] Engine found 7 raw finding(s)
[Permi] Running AI filter on 7 finding(s)...

════════════════════════════════════════════════════════════════════════
  FILTER SUMMARY
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

  [1] [HIGH] SQL001  SQL Injection — string concatenation
  File      : app/routes/users.py:42
  Fix       : Use parameterised queries: cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
  AI        : REAL [94% confidence]  User input is concatenated directly into the query string.

  Scan completed in 4s
```

---

## CLI Reference

```
permi scan PATH                  Scan local codebase or GitHub repo
  --severity LEVEL               critical | high | medium | low | all (default: all)
  --offline                      Skip AI filter, show raw findings
  --output FORMAT                human (default) | json
  --export FILE                  Export full report (.txt, .json, .md, .docx)
  --project NAME                 Project name for the database

permi setup --community          Register for 50 free AI filter credits
permi setup --api-key KEY        Use your own OpenRouter API key (unlimited)
permi info                       Show config and credit status
permi feedback                   Share feedback with the Permi team
```

---

## CI/CD Integration

Permi exits with code `1` if any HIGH severity findings are confirmed after filtering. Use this in any pipeline:

```yaml
# GitHub Actions — inline (without the Marketplace Action)
- name: Run Permi security scan
  run: |
    pip install permi
    permi setup --api-key ${{ secrets.OPENROUTER_API_KEY }}
    permi scan . --severity high --output json --export permi-report.json
```

```bash
# Fail the build on high severity findings
permi scan ./myapp --severity high || exit 1
```

---

## Changelog

### v0.3.1 — Codebase-only focus
- **REMOVED:** Live URL/web scanning (`--url`, `--js`, `--js-timeout`, `--include-subdomains`, `--max-pages`). Permi now focuses exclusively on source code scanning, which is where the AI filter, fix templates, and compliance mapping add the most value. `--path` is also gone — pass the path positionally: `permi scan ./myapp` instead of `permi scan --path ./myapp`.
- **CHANGED:** `.docx` exports now automatically write a matching `.md` alongside them with the full findings list, for technical review.
- **CHANGED:** Exporting without a folder in the filename now prints an explicit notice that the report is being saved to the default `~/.permi/exports/` location.
- **CHANGED:** The feedback prompt no longer shows after every scan — it appears at most once every 10-15 scans.
- **REMOVED:** `permi[js]` extra (Playwright/playwright-stealth) and the `httpx`/`beautifulsoup4` dependencies.

### v0.2.17 — Precision improvements
- **FIX:** Windows Defender freeze — DB path now resolves lazily, not at import time
- **FIX:** XSS false positives — proper HTML entity encoding check before flagging
- **FIX:** Boolean SQLi false positives — both responses must exceed 2000 bytes
- **FIX:** Time-based SQLi — requires minimum 8s hard threshold, not just baseline + 4s
- **FIX:** Tracking parameters (utm_*, ref_*, locale) now fully skipped in all scanners
- **NEW:** Progress indicator during web scan — scan never looks frozen
- **NEW:** `pip install "permi[js]"` installs Playwright dependencies automatically
- **NEW:** `permi info` shows playwright-stealth installation status

### v0.2.13 — JS/SPA Support + GitHub Action
- **NEW:** `--js` flag for JavaScript-rendered applications (React, Vue, Angular, Next.js)
- **NEW:** Playwright headless browser integration with stealth mode
- **NEW:** Network interception — discovers XHR/fetch API endpoints automatically
- **NEW:** SPA detection warning with exact re-run command shown to user
- **NEW:** [Permi GitHub Action](https://github.com/marketplace/actions/permi-security-scanner)
- **NEW:** Windows antivirus freeze detection and guidance
- **NEW:** Scan timer — total duration shown at end of every scan

### v0.2.2 — AI Filter + Community Proxy
- Precision filter with three-tier verdict: REAL / REVIEW / FP with 0–100 confidence score
- Community proxy — 50 free credits with `permi setup --community`
- OpenRouter API key support
- Inline fix templates — exact remediation per finding
- `--export` flag — save full reports as .txt, .json, or .md
- `--include-subdomains` flag
- Feedback system — `permi feedback`

### v0.1 — Foundation
- CLI scanner (web + static analysis)
- PyPI distribution (`pip install permi`)
- 17 detection rules across SQL, XSS, secrets, USSD, insecure practices
- SQLite database at `~/.permi/permi.db`

---

## Contributing

Pull requests welcome. Please open an issue first to discuss significant changes.

If you find a vulnerability in a real application using Permi, please report it responsibly to the affected organisation before disclosing publicly. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide, including how to write new vulnerability rules.

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
