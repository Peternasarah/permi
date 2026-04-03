## Summary

<!-- One sentence: what does this PR do? -->



## Type of change

<!-- Check all that apply -->

- [ ] Bug fix — fixes an incorrect or broken behaviour
- [ ] New vulnerability rule — adds a new detection pattern
- [ ] New feature — adds functionality that did not exist before
- [ ] Refactor — improves code structure without changing behaviour
- [ ] Documentation — improves docs, README, or inline comments
- [ ] Dependency update — updates a package version
- [ ] CI/CD — changes to the build or test pipeline

---

## What changed and why

<!-- Explain the change in enough detail that a reviewer understands
     the reasoning, not just the mechanics. Why this approach? Why now? -->



---

## Testing

<!-- How did you verify this works? -->

- [ ] Ran `permi scan --path ./test_project --offline` — existing findings unchanged
- [ ] Ran `permi scan --path ./test_project` — AI filter still works
- [ ] Added a test case to `test_project/` that triggers the new rule (if adding a rule)
- [ ] Tested on Windows / macOS / Linux (check what you tested on)

**Output of `permi scan --path ./test_project --offline` after this change:**

```
<!-- Paste the summary line here, e.g.:
[Permi] Done — 9 raw findings, 6 real  |  3 false positive(s) removed -->
```

---

## New vulnerability rule checklist (skip if not adding a rule)

- [ ] Rule ID follows the naming convention (e.g., `SQL003`, `USSD002`)
- [ ] `severity` is appropriate (`high` / `medium` / `low`)
- [ ] `description` explains both the vulnerability and the attacker's ability
- [ ] Pattern was tested against real vulnerable code and correctly flags it
- [ ] Pattern does not fire on obviously safe code (low false positive rate)
- [ ] A test case in `test_project/` triggers this rule

**Rule ID and name:**

```
<!-- e.g., INS006 — Insecure — subprocess with shell=True on user input -->
```

---

## Breaking changes

- [ ] This PR introduces breaking changes

<!-- If checked, describe what breaks and how users should migrate: -->



---

## Related issues

<!-- Link any related issues: -->
Closes #
Relates to #

---

## Screenshots or output (optional)

<!-- Paste terminal output, before/after comparisons, or anything else
     that helps reviewers understand the change visually. -->
