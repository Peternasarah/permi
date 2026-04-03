# Contributing to Permi

Thank you for considering a contribution to Permi. This project exists to give
Nigerian developers and global SMBs a security tool that actually understands
their context. Every contribution — code, documentation, bug report, or new
vulnerability rule — moves that mission forward.

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

- Read the [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). It is short and important.
- Check [open issues](https://github.com/peternasarah/permi/issues) before starting
  work — someone may already be building what you have in mind.
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
| **New vulnerability rules** | Patterns specific to Nigerian tech stacks, new OWASP findings |
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
git clone https://github.com/peternasarahE/permi.git
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
pip install -r requirements.txt

# 5. Add your OpenRouter API key
echo OPENROUTER_API_KEY=your-key-here > .env

# 6. Verify the setup works
permi scan --path ./test_project --offline
```

You should see Permi scan the test project and print findings. If it does,
your development environment is ready.

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
git checkout -b feature/ndpr-compliance-check
git checkout -b docs/improve-readme
```

**3. Make your changes**
Keep changes focused. One branch = one logical change.

**4. Test your changes**
```bash
# Run a scan against the test project
permi scan --path ./test_project

# Run a scan in offline mode (no API calls)
permi scan --path ./test_project --offline

# If you added new rules, add a test case to test_project/ that triggers them
# and verify they are caught
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

### Rule ID prefixes

| Prefix | Category |
|--------|----------|
| `SQL`  | SQL Injection |
| `XSS`  | Cross-Site Scripting |
| `SEC`  | Hardcoded Secrets |
| `INS`  | Insecure Practices |
| `USSD` | USSD / Nigerian-specific |
| `API`  | API Security |
| `NDPR` | NDPR Compliance |
| `MOB`  | Mobile Security |

Use the next available number in the relevant prefix series.

### Rule quality checklist

Before submitting a new rule, verify:

- [ ] The pattern catches the vulnerability it targets on a real code example
- [ ] The pattern does not fire on obviously safe code (low false positive rate)
- [ ] The `description` explains both the risk and the attacker's ability
- [ ] The `severity` is appropriate:
  - `high` — exploitable directly, leads to data loss, code execution, or
    credential exposure
  - `medium` — exploitable under certain conditions, or increases attack surface
  - `low` — informational, best practice violation, minor exposure
- [ ] A test case exists in `test_project/` that triggers the rule

### Nigerian-specific rules

Permi's competitive advantage is context. Rules that address:
- USSD gateway vulnerabilities
- Mobile money API misconfigurations
- NDPR compliance gaps
- Local payment gateway (Paystack, Flutterwave) credential exposure

...are especially valuable and will be prioritised for review.

---

## Code Style

- **Python version:** 3.9+ compatible syntax only
- **Formatting:** Follow PEP 8. Keep lines under 90 characters where practical.
- **Type hints:** Use them on all function signatures
- **Comments:** Explain *why*, not *what*. The code shows what — comments
  explain the reasoning behind non-obvious decisions.
- **No external formatting tools are required** — but your code should be
  readable without them.

---

## Commit Message Format

Use this format for all commits:

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
fix(engine): skip binary files that cause UnicodeDecodeError
docs(readme): add offline mode usage example
refactor(filter): extract verdict parsing into separate function
```

---

## Pull Request Guidelines

A good pull request:

- **Has a clear title** using the same format as commit messages
- **Describes what changed and why** — not just what the code does
- **Is focused** — one logical change per PR. Large PRs are harder to review
  and slower to merge.
- **Includes a test** — if you added a rule, add a code example to
  `test_project/` that triggers it
- **Does not break existing behaviour** — run `permi scan --path ./test_project
  --offline` and confirm the same findings appear

### PR description template

When you open a pull request, a template will appear automatically.
Fill it in completely — PRs without descriptions take longer to review.

---

## What Gets Accepted

Permi has a focused scope. The following will generally be accepted:

- Bug fixes
- New vulnerability rules with low false positive rates
- Nigerian / African market-specific security checks
- Documentation improvements
- Performance improvements to the scanner engine
- Improved AI prompts that reduce false positives

The following require prior discussion before work begins:

- New CLI commands or flags
- Changes to the database schema
- New external dependencies
- Architectural changes to the scanner pipeline

The following will not be accepted:

- Rules with very high false positive rates that the AI filter cannot
  reliably clean up
- Dependencies that cannot run offline
- Changes that break the `--offline` flag
- Code that phones home, collects analytics, or makes unexpected network calls

---

## Licensing of Contributions

By submitting a contribution, you agree that it will be licensed under the
[Permi Community License](LICENSE). You retain copyright of your own
contributions, but grant Permi the rights described in Part 4 of the license.

If you are contributing on behalf of an employer, ensure you have the right
to make the contribution before submitting.

---

## Questions?

Open a [GitHub Discussion](https://github.com/peternasarah/permi/discussions) or
reach out on Twitter: [@pndash](https://twitter.com/peternasarah)

Thank you for contributing to Permi.

*Built in Nigeria. For Nigeria. Then for the World.*
