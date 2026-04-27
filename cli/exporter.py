# cli/exporter.py
# Handles exporting scan results to file.
# Supports three formats inferred from file extension:
#   .txt  — plain text (same as terminal output but complete, no truncation)
#   .json — structured JSON (machine-readable, good for pipelines)
#   .md   — markdown (good for GitHub issues, reports, documentation)
#
# Usage:
#   permi scan --path ./myapp --export_file results.txt
#   permi scan --url https://site.com --export report.md
#   permi scan --path ./myapp --export findings.json

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime


def _severity_emoji(sev: str) -> str:
    return {"high": "🔴", "medium": "🟡", "low": "🔵"}.get(sev, "⚪")


def _verdict_label(verdict: str | None, confidence: int | None) -> str:
    if not verdict:
        return ""
    conf_str = f" [{confidence}%]" if confidence is not None else ""
    labels = {
        "REAL":           f"REAL{conf_str}",
        "REVIEW":         f"REVIEW — manual check needed{conf_str}",
        "AI_UNAVAILABLE": "AI UNAVAILABLE — review manually",
        "FP":             "FALSE POSITIVE",
    }
    return labels.get(verdict, verdict)


# ── PLAIN TEXT EXPORT ─────────────────────────────────────────────────────────

def _to_text(
    findings:   list[dict],
    raw_count:  int,
    scan_target: str,
    info:        dict | None = None,
) -> str:
    lines = []
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines.append("=" * 72)
    lines.append("  PERMI — AI-POWERED VULNERABILITY SCANNER")
    lines.append("  Built in Nigeria. For Nigeria. Then for the World.")
    lines.append("  github.com/Peternasarah/permi")
    lines.append("=" * 72)
    lines.append(f"  Scan target : {scan_target}")
    lines.append(f"  Exported at : {ts}")
    lines.append("=" * 72)
    lines.append("")

    # Web scan target info
    if info:
        lines.append("TARGET INFORMATION")
        lines.append("-" * 60)
        for k, v in info.items():
            if k not in ("timestamp", "error") and v:
                lines.append(f"  {k:<20}: {v}")
        lines.append("")

    # AI filter summary
    if raw_count > 0:
        real_count   = sum(1 for f in findings if f.get("ai_verdict") == "REAL")
        review_count = sum(1 for f in findings if f.get("ai_verdict") in ("REVIEW", "AI_UNAVAILABLE"))
        fp_count     = raw_count - len(findings)
        noise_pct    = int((fp_count / raw_count) * 100) if raw_count > 0 else 0

        lines.append("AI FILTER SUMMARY")
        lines.append("=" * 72)
        lines.append(f"  Raw findings     : {raw_count}")
        lines.append(f"  Confirmed real   : {real_count}")
        if review_count:
            lines.append(f"  Needs review     : {review_count}")
        lines.append(f"  False positives  : {fp_count} removed ({noise_pct}% noise reduction)")
        lines.append("")

        high   = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")
        low    = sum(1 for f in findings if f.get("severity") == "low")
        lines.append(f"  High    : {high}")
        lines.append(f"  Medium  : {medium}")
        lines.append(f"  Low     : {low}")
        lines.append("=" * 72)
        lines.append("")

    if not findings:
        lines.append("  No real vulnerabilities found.")
        lines.append("")
        return "\n".join(lines)

    lines.append(f"FINDINGS ({len(findings)} total)")
    lines.append("")

    for i, f in enumerate(findings, 1):
        sev     = f.get("severity", "low").upper()
        rule_id = f.get("rule_id", "")
        name    = f.get("rule_name", "")

        lines.append("-" * 72)
        lines.append(f"  [{i}] [{sev}] {rule_id}  {name}")
        lines.append("")

        # Path scan fields
        if f.get("line_number") is not None and f.get("line_number") != 0:
            lines.append(f"  File  : {f.get('file', '—')}")
            lines.append(f"  Line  : {f.get('line_number', '?')}")
            lines.append(f"  Code  : {f.get('line_content', '—')}")
        else:
            # Web scan fields
            lines.append(f"  URL      : {f.get('file', '—')}")
            if f.get("parameter"):
                lines.append(f"  Parameter: {f.get('parameter')}")
            if f.get("payload"):
                lines.append(f"  Payload  : {f.get('payload')}")
            if f.get("evidence"):
                lines.append(f"  Evidence : {f.get('evidence')}")

        lines.append(f"  Why   : {f.get('description', '—')}")

        # Fix template
        fix = _get_fix(rule_id)
        if fix:
            for j, fix_line in enumerate(fix.split("\n")):
                prefix = "  Fix   : " if j == 0 else "          "
                lines.append(f"{prefix}{fix_line}")

        # AI verdict
        verdict    = f.get("ai_verdict")
        confidence = f.get("ai_confidence")
        if verdict:
            lines.append(f"  AI    : {_verdict_label(verdict, confidence)}")
            if f.get("ai_explanation"):
                lines.append(f"          {f.get('ai_explanation')}")

        lines.append("")

    lines.append("=" * 72)
    lines.append("  SCAN COMPLETE")
    lines.append(f"  {len(findings)} finding(s)  |  {raw_count - len(findings)} false positive(s) removed")
    lines.append("=" * 72)
    lines.append("")

    return "\n".join(lines)


# ── JSON EXPORT ───────────────────────────────────────────────────────────────

def _to_json(
    findings:    list[dict],
    raw_count:   int,
    scan_target: str,
    info:        dict | None = None,
) -> str:
    fp_count   = raw_count - len(findings)
    noise_pct  = int((fp_count / raw_count) * 100) if raw_count > 0 else 0

    output = {
        "permi_version":  _get_version(),
        "scan_target":    scan_target,
        "exported_at":    datetime.now().isoformat(),
        "summary": {
            "raw_count":         raw_count,
            "real_count":        len(findings),
            "false_positives":   fp_count,
            "noise_reduction_pct": noise_pct,
            "high":   sum(1 for f in findings if f.get("severity") == "high"),
            "medium": sum(1 for f in findings if f.get("severity") == "medium"),
            "low":    sum(1 for f in findings if f.get("severity") == "low"),
        },
        "target_info": info or {},
        "findings": [
            {k: v for k, v in f.items() if v is not None}
            for f in findings
        ],
    }

    return json.dumps(output, indent=2)


# ── MARKDOWN EXPORT ───────────────────────────────────────────────────────────

def _to_markdown(
    findings:    list[dict],
    raw_count:   int,
    scan_target: str,
    info:        dict | None = None,
) -> str:
    lines = []
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines.append("# Permi Security Scan Report")
    lines.append("")
    lines.append(f"**Target:** `{scan_target}`  ")
    lines.append(f"**Exported:** {ts}  ")
    lines.append(f"**Tool:** [Permi](https://github.com/Peternasarah/permi) — AI-Powered Vulnerability Scanner  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Web scan target info
    if info:
        lines.append("## Target Information")
        lines.append("")
        lines.append("| Property | Value |")
        lines.append("|----------|-------|")
        for k, v in info.items():
            if k not in ("timestamp", "error") and v:
                lines.append(f"| {k} | {v} |")
        lines.append("")

    # Summary
    if raw_count > 0:
        fp_count   = raw_count - len(findings)
        noise_pct  = int((fp_count / raw_count) * 100) if raw_count > 0 else 0
        high       = sum(1 for f in findings if f.get("severity") == "high")
        medium     = sum(1 for f in findings if f.get("severity") == "medium")
        low        = sum(1 for f in findings if f.get("severity") == "low")

        lines.append("## AI Filter Summary")
        lines.append("")
        lines.append(f"> **{noise_pct}% noise reduction** — {fp_count} false positive(s) removed from {raw_count} raw findings")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Raw findings | {raw_count} |")
        lines.append(f"| Real issues | **{len(findings)}** |")
        lines.append(f"| False positives removed | {fp_count} ({noise_pct}%) |")
        lines.append(f"| 🔴 High | {high} |")
        lines.append(f"| 🟡 Medium | {medium} |")
        lines.append(f"| 🔵 Low | {low} |")
        lines.append("")

    if not findings:
        lines.append("## ✅ No Real Vulnerabilities Found")
        lines.append("")
        return "\n".join(lines)

    lines.append(f"## Findings ({len(findings)})")
    lines.append("")

    for i, f in enumerate(findings, 1):
        sev     = f.get("severity", "low")
        emoji   = _severity_emoji(sev)
        rule_id = f.get("rule_id", "")
        name    = f.get("rule_name", "")
        verdict = f.get("ai_verdict")
        confidence = f.get("ai_confidence")

        lines.append(f"### {i}. {emoji} `{rule_id}` — {name}")
        lines.append("")
        lines.append(f"**Severity:** {sev.upper()}  ")

        if f.get("line_number") and f.get("line_number") != 0:
            lines.append(f"**File:** `{f.get('file', '—')}`  ")
            lines.append(f"**Line:** {f.get('line_number', '?')}  ")
            lines.append("")
            lines.append(f"```")
            lines.append(f"{f.get('line_content', '—')}")
            lines.append(f"```")
        else:
            lines.append(f"**URL:** `{f.get('file', '—')}`  ")
            if f.get("parameter"):
                lines.append(f"**Parameter:** `{f.get('parameter')}`  ")
            if f.get("payload"):
                lines.append(f"**Payload:** `{f.get('payload')}`  ")
            if f.get("evidence"):
                lines.append(f"**Evidence:** {f.get('evidence')}  ")

        lines.append("")
        lines.append(f"**Why this matters:** {f.get('description', '—')}")
        lines.append("")

        fix = _get_fix(rule_id)
        if fix:
            lines.append("**Recommended fix:**")
            lines.append("")
            lines.append(f"```")
            lines.append(fix)
            lines.append(f"```")
            lines.append("")

        if verdict:
            v_label = _verdict_label(verdict, confidence)
            lines.append(f"**AI verdict:** {v_label}  ")
            if f.get("ai_explanation"):
                lines.append(f"**AI reasoning:** {f.get('ai_explanation')}  ")
            lines.append("")

        lines.append("---")
        lines.append("")

    lines.append("*Report generated by [Permi](https://pypi.org/project/permi/) — ")
    lines.append("Built in Nigeria. For Nigeria. Then for the World.*")
    lines.append("")

    return "\n".join(lines)


# ── HELPERS ───────────────────────────────────────────────────────────────────

def _get_fix(rule_id: str) -> str | None:
    try:
        from scanner.rules import FIX_TEMPLATES
        return FIX_TEMPLATES.get(rule_id)
    except ImportError:
        return None


def _get_version() -> str:
    try:
        import importlib.metadata
        return importlib.metadata.version("permi")
    except Exception:
        return "dev"


def _detect_format(filepath: str) -> str:
    """Infer export format from file extension."""
    ext = Path(filepath).suffix.lower()
    if ext == ".json":
        return "json"
    if ext in (".md", ".markdown"):
        return "markdown"
    return "text"  # default for .txt and anything else


# ── PUBLIC API ────────────────────────────────────────────────────────────────

def export(
    filepath:    str,
    findings:    list[dict],
    raw_count:   int,
    scan_target: str,
    info:        dict | None = None,
) -> str:
    """
    Export scan results to a file.

    Format is inferred from file extension:
      .txt  → plain text
      .json → structured JSON
      .md   → markdown

    Returns the resolved absolute file path.
    Raises IOError if the file cannot be written.
    """
    fmt  = _detect_format(filepath)
    path = Path(filepath).resolve()

    if fmt == "json":
        content = _to_json(findings, raw_count, scan_target, info)
    elif fmt == "markdown":
        content = _to_markdown(findings, raw_count, scan_target, info)
    else:
        content = _to_text(findings, raw_count, scan_target, info)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

    return str(path)
