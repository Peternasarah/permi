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

A good report helps us understand, reproduce, and fix the issue quickly.
Please include as much of the following as possible:

- **Description** — What is the vulnerability? What does it allow an attacker
  to do?
- **Affected component** — Which module, function, or feature is affected?
  (e.g., `scanner/engine.py`, the CLI argument parser, the SQLite layer)
- **Steps to reproduce** — Exact commands or code that trigger the issue
- **Proof of concept** — A minimal example demonstrating the vulnerability,
  if possible
- **Impact assessment** — In your judgement, how severe is this? What is the
  worst-case scenario for a Permi user?
- **Suggested fix** — If you have one (optional but appreciated)

---

## What Happens After You Report

| Timeline | Action |
|----------|--------|
| Within 48 hours | Acknowledgement of your report |
| Within 7 days | Initial assessment — confirmed, investigating, or not reproducible |
| Within 30 days | Fix developed and tested (for confirmed vulnerabilities) |
| After fix is released | Public disclosure (coordinated with you) |

We will keep you informed throughout the process. If we need more information,
we will contact you directly.

---

## Coordinated Disclosure

We follow a coordinated disclosure model:

1. You report the vulnerability privately
2. We confirm and fix it
3. We release the fix in a new version
4. We publicly disclose the vulnerability and credit you (unless you prefer
   to remain anonymous)

We ask that you give us a reasonable time to fix the issue — typically 30 days
— before any public disclosure. If a fix requires more time, we will discuss
an extended timeline with you.

---

## Scope

The following are in scope for security reports:

- **Permi CLI** — command injection, path traversal, unsafe file handling
- **Scanner engine** — rule bypass, malicious input handling
- **AI filter** — prompt injection that causes incorrect verdicts
- **Database layer** — SQL injection, data leakage between projects
- **Dependency vulnerabilities** — known CVEs in Permi's dependencies
  that affect users

The following are out of scope:

- Vulnerabilities in code that Permi *scans* (that is expected behaviour)
- Issues that require physical access to the user's machine
- Social engineering attacks
- Theoretical vulnerabilities with no practical exploit path
- Findings from automated scanners without manual verification

---

## Supported Versions

We actively maintain and patch the latest released version of Permi.

| Version | Supported |
|---------|-----------|
| Latest (PyPI) | ✅ Yes |
| Previous minor versions | ⚠️ Critical fixes only |
| Versions more than 2 behind | ❌ No |

If you are running an older version, upgrade to the latest before reporting
to confirm the issue still exists.

---

## Recognition

We appreciate responsible disclosure. Reporters of confirmed, significant
vulnerabilities will be:

- Credited in the release notes (unless anonymity is requested)
- Listed in our Hall of Fame (coming soon at trypermi.dev/security)

We do not currently offer a paid bug bounty program. If this changes,
it will be announced on our GitHub and website.

---

## A Note on Irony

Yes — we are a security scanner that could itself have vulnerabilities.
We find this motivating, not embarrassing. Finding and fixing security issues
in Permi makes every user safer. Thank you for helping us hold ourselves to
the same standard we ask of others.

---

*Built in Nigeria. For Nigeria. Then for the World.*

Permi — github.com/peternasarah/permi
