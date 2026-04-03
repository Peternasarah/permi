# cli/formatter.py
# Handles all terminal output formatting.
# Keeps colour logic completely separate from scan logic.

from colorama import init, Fore, Style

# Initialise colorama — required on Windows for ANSI colours to work
init(autoreset=True)

# Severity colours
SEVERITY_COLOUR = {
    "high":   Fore.RED,
    "medium": Fore.YELLOW,
    "low":    Fore.CYAN,
}

VERDICT_COLOUR = {
    "REAL": Fore.RED,
    "FP":   Fore.GREEN,
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


def print_finding(finding: dict, index: int) -> None:
    """
    Print a single finding as a formatted block.
    Each finding gets a numbered header, severity badge,
    file location, code snippet, AI verdict, and explanation.
    """
    sev    = finding.get("severity", "low")
    colour = SEVERITY_COLOUR.get(sev, Fore.WHITE)

    _divider()

    # ── Header line ───────────────────────────────────────────────────────────
    print(
        Fore.WHITE + Style.BRIGHT + f"  [{index}] " +
        colour + Style.BRIGHT + f"[{sev.upper()}] " +
        Fore.WHITE + Style.BRIGHT + finding.get("rule_id", "") +
        Style.RESET_ALL + "  " +
        finding.get("rule_name", "")
    )

    print()

    # ── File and line ─────────────────────────────────────────────────────────
    print(
        Fore.WHITE + "  File  : " + Style.RESET_ALL +
        finding.get("file", "unknown")
    )
    print(
        Fore.WHITE + "  Line  : " + Style.RESET_ALL +
        str(finding.get("line_number", "?"))
    )

    # ── Code snippet ──────────────────────────────────────────────────────────
    print(
        Fore.WHITE + "  Code  : " + Style.RESET_ALL +
        Fore.YELLOW + finding.get("line_content", "") + Style.RESET_ALL
    )

    # ── Description ───────────────────────────────────────────────────────────
    print(
        Fore.WHITE + "  Why   : " + Style.RESET_ALL +
        finding.get("description", "")
    )

    # ── AI verdict ────────────────────────────────────────────────────────────
    verdict = finding.get("ai_verdict")
    if verdict:
        v_colour = VERDICT_COLOUR.get(verdict, Fore.WHITE)
        print(
            Fore.WHITE + "  AI    : " +
            v_colour + Style.BRIGHT + verdict + Style.RESET_ALL +
            "  " + finding.get("ai_explanation", "")
        )

    print()


def print_results_human(findings: list[dict]) -> None:
    """Print all findings in human-readable coloured format."""
    if not findings:
        print(Fore.GREEN + Style.BRIGHT + "\n  ✅  No real vulnerabilities found.\n")
        return

    for i, finding in enumerate(findings, start=1):
        print_finding(finding, i)

    _divider()


def print_summary(findings: list[dict], raw_count: int) -> None:
    """Print the final summary block."""
    high   = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    low    = sum(1 for f in findings if f["severity"] == "low")
    fp     = raw_count - len(findings)

    print()
    _divider("═")
    print(Fore.WHITE + Style.BRIGHT + "  SCAN SUMMARY")
    _divider("═")
    print(f"  Total findings  : {Style.BRIGHT}{len(findings)}{Style.RESET_ALL}  "
          f"(filtered {fp} false positive(s))")
    print(f"  {Fore.RED}High    : {high}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Medium  : {medium}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Low     : {low}{Style.RESET_ALL}")
    _divider("═")
    print()
