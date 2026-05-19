# Security Policy

## Reporting a Vulnerability in Permi

Permi is a security tool. We hold ourselves to a high standard when it comes
to the security of the tool itself. If you discover a vulnerability in Permi's
code, dependencies, or infrastructure, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**
Public disclosure before a fix is available puts users at risk.

---

## How to Report

Send a detailed report to:

**Email:** dashenasarahpeter@gmail.com
**Subject line:** `[SECURITY] Brief description of the vulnerability`

### What to include

- **Description** — What is the vulnerability? What does it allow an attacker to do?
- **Affected component** — Which module, function, or feature is affected?
- **Steps to reproduce** — Exact commands or code that trigger the issue
- **Proof of concept** — A minimal example, if possible
- **Impact assessment** — How severe is this? What is the worst-case scenario?
- **Suggested fix** — Optional but appreciated

---

## What Happens After You Report

| Timeline | Action |
|----------|--------|
| Within 48 hours | Acknowledgement of your report |
| Within 7 days | Initial assessment — confirmed, investigating, or not reproducible |
| Within 30 days | Fix developed and tested (for confirmed vulnerabilities) |
| After fix is released | Public disclosure, coordinated with you |

---

## Coordinated Disclosure

We follow a coordinated disclosure model:

1. You report the vulnerability privately
2. We confirm and fix it
3. We release the fix in a new version
4. We publicly disclose and credit you (unless you prefer anonymity)

We ask for 30 days before public disclosure. If a fix requires more time,
we will discuss an extended timeline with you.

---

## Scope

**In scope:**

- **Permi CLI** — command injection, path traversal, unsafe file handling,
  Windows freeze exploits, SQLite injection in the local database
- **Scanner engine** — rule bypass, malicious input handling, regex DoS
- **AI filter** — prompt injection that causes systematically incorrect verdicts
- **Database layer** — data leakage between projects, path traversal in DB path
- **Web scanner** — SSRF via crafted target URLs, unintended scanning of out-of-scope hosts
- **GitHub Action** — action injection, secret exposure in logs, GITHUB_TOKEN misuse
- **Community proxy** — token forgery, credit bypass, rate limit evasion
- **Dependency vulnerabilities** — known CVEs in Permi's dependencies

**Out of scope:**

- Vulnerabilities in code that Permi *scans* (that is expected behaviour —
  Permi is supposed to find them)
- Issues that require physical access to the user's machine
- Social engineering attacks
- Theoretical vulnerabilities with no practical exploit path
- Findings from automated scanners run against Permi without manual verification
- The fact that Permi uses `verify=False` in httpx for web scanning —
  this is intentional and documented; Permi is the client, not a server

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (PyPI) | ✅ Yes |
| Previous minor versions | ⚠️ Critical fixes only |
| Versions more than 2 behind | ❌ No |

Upgrade to the latest version before reporting to confirm the issue persists.

---

## Recognition

Reporters of confirmed, significant vulnerabilities will be:

- Credited in the release notes (unless anonymity is requested)
- Listed in our security acknowledgements on the website

We do not currently offer a paid bug bounty program.

---

## A Note on the Irony

Yes — we are a security scanner that could itself have vulnerabilities.
We find this motivating, not embarrassing. Every vulnerability found and
fixed in Permi makes every user's workflow safer. The standard we ask of
others, we ask of ourselves first.

---

*Built in Nigeria. For Nigeria. Then for the World.*

Permi — github.com/peternasarah/permi
