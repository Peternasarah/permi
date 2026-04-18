# cli/formatter.py
# Handles all terminal output formatting.
# Keeps colour logic completely separate from scan logic.

from __future__ import annotations
from collections import Counter
from colorama import init, Fore, Style

init(autoreset=True)

SEVERITY_COLOUR = {
    "high":   Fore.RED,
    "medium": Fore.YELLOW,
    "low":    Fore.CYAN,
}

VERDICT_COLOUR = {
    "REAL":          Fore.RED,
    "FP":            Fore.GREEN,
    "AI_UNAVAILABLE": Fore.YELLOW,
}


def _divider(char="─", width=72, colour=Fore.WHITE):
    print(colour + char * width + Style.RESET_ALL)


def print_banner():
    """Print the Permi header banner."""
    print()
    print(Fore.CYAN + Style.BRIGHT + "┌─────────────────────────────────────────┐")
    print(Fore.CYAN + Style.BRIGHT + "│        Permi — Security Scanner         │")
    print(Fore.CYAN + Style.BRIGHT + "│   Built in Nigeria. For the World.      │")
    print(Fore.CYAN + Style.BRIGHT + "└─────────────────────────────────────────┘")
    print()


def print_ai_summary(findings: list[dict], raw_count: int) -> None:
    """
    Print the AI value summary BEFORE the detailed findings list.
    Shows noise reduction upfront so the value is clear in the first 5 seconds.
    Only shown when there were raw findings to filter.
    """
    if raw_count == 0:
        return

    real_count   = len(findings)
    fp_count     = raw_count - real_count
    unavail      = sum(1 for f in findings if f.get("ai_verdict") == "AI_UNAVAILABLE")
    noise_pct    = int((fp_count / raw_count) * 100) if raw_count > 0 else 0

    high   = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    low    = sum(1 for f in findings if f.get("severity") == "low")

    # Group by rule name for top issues
    rule_counts = Counter(f.get("rule_name", "Unknown") for f in findings
                          if f.get("ai_verdict") != "AI_UNAVAILABLE")

    print()
    _divider("═", colour=Fore.CYAN)
    print(Fore.CYAN + Style.BRIGHT + "  AI FILTER SUMMARY" + Style.RESET_ALL)
    _divider("═", colour=Fore.CYAN)

    print(
        f"  Raw findings     : {Fore.WHITE}{Style.BRIGHT}{raw_count}{Style.RESET_ALL}\n"
        f"  Real issues      : {Fore.WHITE}{Style.BRIGHT}{real_count}{Style.RESET_ALL}\n"
        f"  False positives  : {Fore.GREEN}{Style.BRIGHT}{fp_count} removed{Style.RESET_ALL}"
    )

    if noise_pct > 0:
        bar_filled = noise_pct // 5
        bar        = "█" * bar_filled + "░" * (20 - bar_filled)
        print(f"  Noise reduced by : {Fore.GREEN}{noise_pct}%{Style.RESET_ALL}  [{bar}]")

    if unavail:
        print(
            f"  Manual review    : {Fore.YELLOW}{unavail} finding(s) — "
            f"AI was unavailable{Style.RESET_ALL}"
        )

    if real_count > 0:
        print(f"\n  {Fore.WHITE}{Style.BRIGHT}Severity breakdown:{Style.RESET_ALL}")
        if high:
            print(f"    {Fore.RED}● High   : {high}{Style.RESET_ALL}")
        if medium:
            print(f"    {Fore.YELLOW}● Medium : {medium}{Style.RESET_ALL}")
        if low:
            print(f"    {Fore.CYAN}● Low    : {low}{Style.RESET_ALL}")

        if rule_counts:
            print(f"\n  {Fore.WHITE}{Style.BRIGHT}Top issues to fix:{Style.RESET_ALL}")
            for rule, count in rule_counts.most_common(5):
                # Shorten the rule name if it's too long
                short = rule[:55] + "..." if len(rule) > 55 else rule
                print(f"    {Fore.WHITE}•{Style.RESET_ALL} {count}× {short}")

    _divider("═", colour=Fore.CYAN)
    print(
        f"\n  {Fore.WHITE}Full details below ↓"
        f"{Style.RESET_ALL}\n"
    )


def print_finding(finding: dict, index: int) -> None:
    """Print a single finding as a formatted block."""
    sev    = finding.get("severity", "low")
    colour = SEVERITY_COLOUR.get(sev, Fore.WHITE)

    _divider()

    print(
        Fore.WHITE + Style.BRIGHT + f"  [{index}] " +
        colour + Style.BRIGHT + f"[{sev.upper()}] " +
        Fore.WHITE + Style.BRIGHT + finding.get("rule_id", "") +
        Style.RESET_ALL + "  " +
        finding.get("rule_name", "")
    )
    print()

    print(Fore.WHITE + "  File  : " + Style.RESET_ALL + finding.get("file", "unknown"))
    print(Fore.WHITE + "  Line  : " + Style.RESET_ALL + str(finding.get("line_number", "?")))
    print(Fore.WHITE + "  Code  : " + Style.RESET_ALL + Fore.YELLOW + finding.get("line_content", "") + Style.RESET_ALL)
    print(Fore.WHITE + "  Why   : " + Style.RESET_ALL + finding.get("description", ""))

    verdict = finding.get("ai_verdict")
    if verdict:
        v_colour = VERDICT_COLOUR.get(verdict, Fore.WHITE)
        label    = verdict if verdict != "AI_UNAVAILABLE" else "REVIEW"
        print(
            Fore.WHITE + "  AI    : " +
            v_colour + Style.BRIGHT + label + Style.RESET_ALL +
            "  " + finding.get("ai_explanation", "")
        )
    print()


def print_results_human(findings: list[dict], raw_count: int = 0) -> None:
    """
    Print AI summary first, then all findings in detail.
    raw_count is needed for the summary — pass it from the scan pipeline.
    """
    # AI summary at the top — before the long list
    if raw_count > 0:
        print_ai_summary(findings, raw_count)

    if not findings:
        print(Fore.GREEN + Style.BRIGHT + "\n  ✅  No real vulnerabilities found.\n")
        return

    for i, finding in enumerate(findings, start=1):
        print_finding(finding, i)

    _divider()


def print_summary(findings: list[dict], raw_count: int) -> None:
    """Print the final compact summary block at the very bottom."""
    high   = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    low    = sum(1 for f in findings if f.get("severity") == "low")
    fp     = raw_count - len(findings)

    print()
    _divider("═")
    print(Fore.WHITE + Style.BRIGHT + "  SCAN SUMMARY")
    _divider("═")
    print(
        f"  Total findings  : {Style.BRIGHT}{len(findings)}{Style.RESET_ALL}  "
        f"(filtered {fp} false positive(s))"
    )
    print(f"  {Fore.RED}High    : {high}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Medium  : {medium}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Low     : {low}{Style.RESET_ALL}")
    _divider("═")
    print()
