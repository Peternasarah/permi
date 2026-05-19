# Contributing to Permi

Thank you for considering a contribution to Permi. This project exists to give
African fintech engineering teams a security tool that actually understands
their context — finding real vulnerabilities and filtering out the noise that
causes developers to stop trusting their scanner.

Every contribution — code, documentation, bug report, or new vulnerability
rule — moves that mission forward.

---

## Table of Contents

- [Before You Start](#before-you-start)
- [Ways to Contribute](#ways-to-contribute)
- [Development Setup](#development-setup)
- [Contribution Workflow](#contribution-workflow)
- [Writing Vulnerability Rules](#writing-vulnerability-rules)
- [Code Style](#code-style)
- [Commit Message Format](#commit-message-format)
- [Pull Request Guidelines](#pull-request-guidelines)
- [What Gets Accepted](#what-gets-accepted)
- [Licensing of Contributions](#licensing-of-contributions)

---

## Before You Start

- Read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). It is short and important.
- Check [open issues](https://github.com/peternasarah/permi/issues) before
  starting work — someone may already be building what you have in mind.
- For significant changes (new features, architectural changes), open an issue
  first and describe what you intend to build. This saves you time if the
  direction does not fit the project's roadmap.
- For small fixes (typos, bug fixes, documentation improvements), you can open
  a pull request directly without prior discussion.

---

## Ways to Contribute

### You do not need to write code to contribute

| Type | Examples |
|------|----------|
| **Bug reports** | Scanner misses a real vulnerability, AI filter gives wrong verdict, CLI crashes |
| **New vulnerability rules** | Patterns specific to Nigerian/African tech stacks, new OWASP findings |
| **Documentation** | Clearer README, better examples, translated docs |
| **Testing** | Run Permi on your own projects and report what it misses or misidentifies |
| **Security research** | Responsible disclosure of vulnerabilities in Permi itself (see SECURITY.md) |
| **Code** | Bug fixes, performance improvements, new features |

---

## Development Setup

### Requirements

- Python 3.9 or higher
- Git
- A free [OpenRouter](https://openrouter.ai) API key (for AI filter testing)

### Steps

```bash
# 1. Fork the repository on GitHub, then clone your fork
git clone https://github.com/peternasarah/permi.git
cd permi

# 2. Create a virtual environment
python -m venv venv

# 3. Activate it
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# 4. Install in editable mode with all dependencies
pip install -e .

# 5. Add your OpenRouter API key
echo OPENROUTER_API_KEY=your-key-here > .env

# 6. Verify the setup works
permi scan --path ./test_project --offline
```

You should see Permi scan the test project and print findings. If it does,
your development environment is ready.

### Optional — JavaScript scanning

```bash
pip install playwright playwright-stealth
playwright install chromium
```

---

## Contribution Workflow

```
1. Fork → 2. Branch → 3. Build → 4. Test → 5. Commit → 6. Pull Request
```

### Step by step

**1. Fork the repository**
Click "Fork" on GitHub. Work on your fork, not the main repository.

**2. Create a branch**
Name your branch clearly:
```bash
git checkout -b fix/sql-rule-false-positive
git checkout -b feature/ndpa-compliance-check
git checkout -b docs/improve-readme
```

**3. Make your changes**
Keep changes focused. One branch = one logical change.

**4. Test your changes**
```bash
# Run a scan against the test project
permi scan --path ./test_project

# Run in offline mode (no API calls)
permi scan --path ./test_project --offline

# If you added new rules, add a test case to test_project/
# that triggers them and verify they are caught
```

**5. Commit with a clear message** (see format below)

**6. Push and open a pull request**
```bash
git push origin your-branch-name
```
Then open a pull request on GitHub against the `main` branch.

---

## Writing Vulnerability Rules

New rules are the most valuable contribution you can make to Permi. Each rule
added to `scanner/rules.py` extends what every Permi user can detect.

Permi's competitive advantage is precision and context. A rule that fires on
10 findings and is right 9 times is more valuable than a rule that fires on
100 findings and is right 30 times.

### Rule structure

```python
{
    "id": "XYZ001",           # Unique ID — use a new prefix for new categories
    "name": "Short name",     # Human-readable, under 60 characters
    "severity": "high",       # high / medium / low
    "description": (
        "What this vulnerability is and why it is dangerous. "
        "What an attacker can do if they exploit it. "
        "One to three sentences."
    ),
    "pattern": re.compile(
        r"your_regex_pattern",
        re.IGNORECASE         # include if pattern should be case-insensitive
    ),
}
```

And add a corresponding fix template to `FIX_TEMPLATES` in `scanner/rules.py`:

```python
"XYZ001": (
    "How to fix this. Concrete code example preferred. "
    "Under 200 characters."
),
```

### Rule ID prefixes

| Prefix | Category |
|--------|----------|
| `SQL`  | SQL Injection |
| `XSS`  | Cross-Site Scripting |
| `SEC`  | Hardcoded Secrets |
| `INS`  | Insecure Practices |
| `USSD` | USSD / Nigerian-specific |
| `API`  | API Security |
| `NDPA` | NDPA Compliance *(Pro tier — see roadmap)* |
| `CBN`  | CBN CSAT compliance *(Pro tier)* |
| `MOB`  | Mobile Security |

### Rule quality checklist

Before submitting a new rule, verify:

- [ ] The pattern catches the vulnerability it targets on a real code example
- [ ] The pattern does not fire on obviously safe code (low false positive rate)
- [ ] The `description` explains both the risk and the attacker's ability
- [ ] A `FIX_TEMPLATE` entry exists with a concrete remediation example
- [ ] The `severity` is appropriate:
  - `high` — exploitable directly, leads to data loss, code execution, or credential exposure
  - `medium` — exploitable under certain conditions, or increases attack surface
  - `low` — informational, best practice violation, minor exposure
- [ ] A test case exists in `test_project/` that triggers the rule

### African/Nigerian-specific rules — highest priority

Permi's strongest differentiator is context. Rules that address the following
are especially valuable and will be prioritised for review:

- USSD gateway vulnerabilities
- Paystack / Flutterwave / Monnify / Opay credential exposure
- BVN / NIN pattern exposure (NDPA-sensitive)
- Mobile money API misconfigurations
- Weak callback endpoint validation

These are patterns that Semgrep, Snyk, and GitHub Advanced Security will never
prioritise for their global ruleset. They are Permi's moat.

---

## Code Style

- **Python version:** 3.9+ compatible syntax only
- **Formatting:** Follow PEP 8. Keep lines under 90 characters where practical.
- **Type hints:** Use them on all function signatures
- **Comments:** Explain *why*, not *what*. The code shows what — comments
  explain the reasoning behind non-obvious decisions.
- **Imports:** All heavy imports (scanner, db, ai_filter) must stay inside
  functions, not at module level. This prevents Windows Defender freeze on startup.

---

## Commit Message Format

```
type(scope): short description

Optional longer explanation if the change is not self-evident.
```

**Types:**

| Type | When to use |
|------|-------------|
| `feat` | New feature or rule |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or updating tests |
| `chore` | Build process, dependencies, tooling |

**Examples:**

```
feat(rules): add Paystack secret key detection rule SEC004
fix(web_scanner): skip tracking params to reduce XSS false positives
docs(readme): add Windows Defender freeze fix instructions
refactor(db): make DB_PATH lazy to fix Windows startup freeze
```

---

## Pull Request Guidelines

A good pull request:

- **Has a clear title** using the same format as commit messages
- **Describes what changed and why** — not just what the code does
- **Is focused** — one logical change per PR
- **Includes a test** — if you added a rule, add a code example to
  `test_project/` that triggers it
- **Does not break existing behaviour** — run
  `permi scan --path ./test_project --offline` and confirm findings appear

---

## What Gets Accepted

**Will generally be accepted:**
- Bug fixes
- New vulnerability rules with low false positive rates
- Nigerian / African market-specific security checks
- Documentation improvements
- Performance improvements to the scanner engine
- Improved AI prompts that reduce false positives

**Require prior discussion:**
- New CLI commands or flags
- Changes to the database schema
- New external dependencies
- Architectural changes to the scanner pipeline

**Will not be accepted:**
- Rules with very high false positive rates
- Dependencies that cannot run offline
- Changes that break the `--offline` flag
- Module-level imports that trigger filesystem access at startup
- Code that phones home, collects analytics, or makes unexpected network calls
  without explicit user consent

---

## Licensing of Contributions

By submitting a contribution, you agree that it will be licensed under the
[Permi Community License](LICENSE). You retain copyright of your own
contributions, but grant Permi the rights described in the license.

---

## Questions?

Open a [GitHub Discussion](https://github.com/peternasarah/permi/discussions)
or reach out: [@peternasarah](https://twitter.com/peternasarah)

Thank you for contributing to Permi.

*Built in Nigeria. For Nigeria. Then for the World.*
