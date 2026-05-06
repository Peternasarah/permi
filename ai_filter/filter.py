# ai_filter/filter.py
# Takes raw findings, runs each through the LLM analyser,
# saves verdicts to the database, and returns filtered results.
# Shows remaining community credits after each scan if using proxy.

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
    Returns findings with verdict REAL, REVIEW, or AI_UNAVAILABLE.
    FP findings are dropped.
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
    review_count = 0
    unavail      = 0
    last_credits = None
    last_message = None
    backend_used = None

    for i, finding in enumerate(findings, start=1):
        label = f"{finding['rule_id']} line {finding['line_number']}"
        print(f"  [{i}/{len(findings)}] {label} — ", end="", flush=True)

        result     = analyse(finding)
        verdict    = result["ai_verdict"]
        explan     = result["ai_explanation"]
        confidence = result.get("ai_confidence")
        backend    = result.get("ai_backend", "")

        # Track community proxy credits
        if backend == "community":
            backend_used = "community"
            cr = result.get("community_credits_left")
            if cr is not None:
                last_credits = cr
            if result.get("community_message"):
                last_message = result["community_message"]

        conf_str = f" ({confidence}%)" if confidence is not None else ""
        print(f"{verdict}{conf_str}  {explan}")

        if "id" in finding:
            _update_finding_verdict(conn, finding["id"], verdict, explan, confidence)

        if verdict == "FP":
            fp_count += 1
        else:
            if verdict == "REVIEW":
                review_count += 1
            elif verdict == "AI_UNAVAILABLE":
                unavail += 1
            keep.append(result)

    conn.close()

    # ── Filter summary ────────────────────────────────────────────────────────
    parts = [f"{len(keep)} kept", f"{fp_count} false positive(s) removed"]
    if review_count:
        parts.append(f"{review_count} need manual review")
    if unavail:
        parts.append(f"{unavail} AI unavailable")
    print(f"\n[Permi] Filter complete — {' | '.join(parts)}\n")

    # ── Community credits remaining ───────────────────────────────────────────
    if backend_used == "community" and last_credits is not None:
        from colorama import Fore, Style
        if last_credits <= 5:
            colour = Fore.RED
        elif last_credits <= 15:
            colour = Fore.YELLOW
        else:
            colour = Fore.GREEN

        print(
            f"  {colour}[Community] {last_credits} free AI credits remaining.{Style.RESET_ALL}"
        )
        if last_message:
            print(f"  {Fore.CYAN}{last_message}{Style.RESET_ALL}")
        print()

    return keep
