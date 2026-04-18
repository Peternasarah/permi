# ai_filter/filter.py
# Takes a list of raw findings, runs each through the LLM,
# saves the verdict back to the database, and returns only
# the findings the LLM marked as REAL or AI_UNAVAILABLE.
# FP findings are dropped. AI_UNAVAILABLE findings are kept
# and clearly labelled for manual review.

from __future__ import annotations

from ai_filter.llm_client import analyse
from db.database import get_connection


def _update_finding_verdict(conn, finding_id: int, verdict: str, explanation: str) -> None:
    """Write the AI verdict back to the findings table."""
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
        offline:  If True, skip all API calls and return everything as REAL.

    Returns:
        Findings marked REAL or AI_UNAVAILABLE.
        FP findings are dropped entirely.
    """
    if not findings:
        return []

    if offline:
        print("[Permi] Offline mode — AI filter skipped, showing all findings.\n")
        return findings

    print(f"[Permi] Running AI filter on {len(findings)} finding(s)...\n")

    conn         = get_connection()
    keep         = []
    fp_count     = 0
    unavail      = 0

    for i, finding in enumerate(findings, start=1):
        print(f"  [{i}/{len(findings)}] {finding['rule_id']} "
              f"line {finding['line_number']} — ", end="", flush=True)

        result  = analyse(finding)
        verdict = result["ai_verdict"]
        explan  = result["ai_explanation"]

        print(f"{verdict}  {explan}")

        # Save verdict back to DB
        if "id" in finding:
            _update_finding_verdict(conn, finding["id"], verdict, explan)

        if verdict == "FP":
            fp_count += 1
        else:
            # REAL and AI_UNAVAILABLE both kept
            if verdict == "AI_UNAVAILABLE":
                unavail += 1
            keep.append(result)

    conn.close()

    msg = f"\n[Permi] Filter complete — {len(keep)} real  |  {fp_count} false positive(s) removed"
    if unavail:
        msg += f"  |  {unavail} need manual review (AI unavailable)"
    print(msg + "\n")

    return keep
