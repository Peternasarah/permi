# Permi

**AI-powered vulnerability scanner for Nigerian developers and global SMBs.**

Permi scans your code for security vulnerabilities and uses AI to filter out
false positives — so you only see findings that actually matter.

Built in Nigeria. For Nigeria. Then for the world.

---

## What Permi detects

- SQL Injection (string concatenation, f-strings, % formatting)
- Cross-Site Scripting (innerHTML, document.write, Jinja2 |safe)
- Hardcoded secrets (passwords, API keys, AWS keys, Paystack/Flutterwave keys)
- Insecure practices (eval/exec, pickle.loads, SSL verification disabled, debug mode)
- USSD vulnerabilities (Nigerian-specific — unvalidated sessionId, phoneNumber, serviceCode)

---

## Installation
```bash
pip install permi
```

Requires Python 3.9+

---

## Usage

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
permi scan --path ./myapp --severity high
```

**Output as JSON (for CI/CD pipelines):**
```bash
permi scan --path ./myapp --output json
```

**Skip AI filter (offline mode):**
```bash
permi scan --path ./myapp --offline
```

---

## Setup

Permi uses [OpenRouter](https://openrouter.ai) for AI-powered false positive
filtering. Create a free account, generate an API key, and add it to a `.env`
file in your project root:
OPENROUTER_API_KEY=sk-or-your-key-here

No API key? Use `--offline` mode. All findings are shown unfiltered.

---

## Example output
[1] [HIGH] SQL001  SQL Injection — string concatenation
File  : app/auth.py
Line  : 42
Code  : cursor.execute("SELECT * FROM users WHERE name = " + username)
Why   : Raw string concatenation used to build a SQL query.
AI    : REAL  User input is directly embedded into a SQL query with no sanitisation.

---

## Built by

Peter N. D. — Cybersecurity student, University of Jos, Nigeria.

---

*Permi is in active development. Feedback and contributions welcome.*