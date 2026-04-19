# ai_filter/filter.py
# Takes raw findings, runs each through the LLM analyser,
# saves verdicts to the database, and returns filtered results.
#
# Verdict handling:
#   REAL          → kept, shown in full
#   REVIEW        → kept, labelled for manual review (medium confidence)
#   FP            → dropped silently
#   AI_UNAVAILABLE → kept, labelled — never silently promoted to REAL

from __future__ import annotations

from ai_filter.llm_client import analyse
from db.database import get_connection


def _update_finding_verdict(
    conn,
    finding_id: int,
    verdict: str,
    explanation: str,
    confidence: int | None,
) -> None:
    """Write AI verdict and confidence back to the findings table."""
    conn.execute("""
        UPDATE findings
        SET ai_verdict     = ?,
            ai_explanation = ?
        WHERE id = ?
    """, (verdict, explanation, finding_id))
    conn.commit()


def run_filter(findings: list[dict], offline: bool = False) -> list[dict]:
    """
    Run the AI filter over a list of findings.

    Args:
        findings: Raw findings list from the scanner.
        offline:  If True, skip all API calls and return everything as-is.

    Returns:
        Findings with verdict REAL, REVIEW, or AI_UNAVAILABLE.
        FP findings are dropped entirely.
    """
    if not findings:
        return []

    if offline:
        print("[Permi] Offline mode — AI filter skipped, showing all findings.\n")
        return findings

    print(f"[Permi] Running AI filter on {len(findings)} finding(s)...\n")

    conn      = get_connection()
    keep      = []
    fp_count  = 0
    review    = 0
    unavail   = 0

    for i, finding in enumerate(findings, start=1):
        label = f"{finding['rule_id']} line {finding['line_number']}"
        print(f"  [{i}/{len(findings)}] {label} — ", end="", flush=True)

        result     = analyse(finding)
        verdict    = result["ai_verdict"]
        explan     = result["ai_explanation"]
        confidence = result.get("ai_confidence")

        # Build display string
        conf_str = f" ({confidence}%)" if confidence is not None else ""
        print(f"{verdict}{conf_str}  {explan}")

        # Save verdict back to DB
        if "id" in finding:
            _update_finding_verdict(conn, finding["id"], verdict, explan, confidence)

        if verdict == "FP":
            fp_count += 1
        else:
            if verdict == "REVIEW":
                review += 1
            elif verdict == "AI_UNAVAILABLE":
                unavail += 1
            keep.append(result)

    conn.close()

    # ── Filter summary ────────────────────────────────────────────────────────
    parts = [f"{len(keep)} kept", f"{fp_count} false positive(s) removed"]
    if review:
        parts.append(f"{review} need manual review")
    if unavail:
        parts.append(f"{unavail} AI unavailable")

    print(f"\n[Permi] Filter complete — {' | '.join(parts)}\n")

    return keep
