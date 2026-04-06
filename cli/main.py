"""
cli/main.py
Permi command-line interface.
Two scan modes:
  permi scan --url  https://target.com        → live web scanner
  permi scan --path ./folder or github URL    → static source scanner
"""

import json
import sys
import click
from colorama import Fore, Style, init

init(autoreset=True)

from cli.formatter import print_results_human, print_summary
from scanner.scan import scan as scan_path


# ── BANNER ────────────────────────────────────────────────────────────────────
def print_banner():
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
  ██████╗ ███████╗██████╗ ███╗   ███╗██╗
  ██╔══██╗██╔════╝██╔══██╗████╗ ████║██║
  ██████╔╝█████╗  ██████╔╝██╔████╔██║██║
  ██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╔╝██║██║
  ██║     ███████╗██║  ██║██║ ╚═╝ ██║██║
  ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝
{Style.RESET_ALL}
{Fore.WHITE}{Style.BRIGHT}  AI-Powered Vulnerability Scanner{Style.RESET_ALL}
{Fore.CYAN}  Built in Nigeria. For Nigeria. Then for the World.{Style.RESET_ALL}
{Fore.WHITE}  github.com/Peternasarah/permi  ·  pypi.org/project/permi{Style.RESET_ALL}
"""
    print(banner)


def print_web_info(info: dict):
    """Print the target info block after a web scan."""
    print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  TARGET INFORMATION{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
    print(f"  {'Target':<18}: {info.get('target', '—')}")
    print(f"  {'IP Address':<18}: {info.get('ip', '—')}")
    print(f"  {'Status Code':<18}: {info.get('status_code', '—')}")
    print(f"  {'Server':<18}: {info.get('server', '—')}")
    print(f"  {'Powered By':<18}: {info.get('powered_by', '—')}")
    print(f"  {'HTTPS':<18}: {'Yes' if info.get('https') else 'No'}")
    print(f"  {'URLs Discovered':<18}: {info.get('urls_discovered', 0)}")
    print(f"  {'URLs Tested':<18}: {info.get('urls_tested', 0)}")
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}\n")


def print_web_finding(finding: dict, index: int):
    """Print a single web scan finding."""
    sev    = finding.get("severity", "low")
    colors = {"high": Fore.RED, "medium": Fore.YELLOW, "low": Fore.CYAN}
    color  = colors.get(sev, Fore.WHITE)

    print(f"{Fore.WHITE}{'─' * 72}{Style.RESET_ALL}")
    print(
        f"  {Fore.WHITE}{Style.BRIGHT}[{index}]{Style.RESET_ALL} "
        f"{color}{Style.BRIGHT}[{sev.upper()}]{Style.RESET_ALL} "
        f"{Fore.WHITE}{Style.BRIGHT}{finding.get('rule_id', '')}{Style.RESET_ALL}  "
        f"{finding.get('rule_name', '')}"
    )
    print()
    print(f"  {Fore.WHITE}URL      :{Style.RESET_ALL} {finding.get('file', '—')}")

    if finding.get("parameter"):
        print(f"  {Fore.WHITE}Parameter:{Style.RESET_ALL} {finding.get('parameter', '—')}")

    if finding.get("payload"):
        print(f"  {Fore.WHITE}Payload  :{Style.RESET_ALL} {Fore.YELLOW}{finding.get('payload', '—')}{Style.RESET_ALL}")

    print(f"  {Fore.WHITE}Evidence :{Style.RESET_ALL} {finding.get('evidence', '—')}")
    print(f"  {Fore.WHITE}Why      :{Style.RESET_ALL} {finding.get('description', '—')}")

    verdict = finding.get("ai_verdict")
    if verdict:
        vc = Fore.RED if verdict == "REAL" else Fore.GREEN
        print(
            f"  {Fore.WHITE}AI       :{Style.RESET_ALL} "
            f"{vc}{Style.BRIGHT}{verdict}{Style.RESET_ALL}  "
            f"{finding.get('ai_explanation', '')}"
        )
    print()


def print_web_results(findings: list, raw_count: int):
    """Print all web findings + summary."""
    if not findings:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}  ✅  No vulnerabilities found.\n{Style.RESET_ALL}")
        return

    for i, f in enumerate(findings, 1):
        print_web_finding(f, i)

    high   = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    low    = sum(1 for f in findings if f.get("severity") == "low")
    fp     = raw_count - len(findings)

    print(f"\n{'═' * 72}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  SCAN SUMMARY{Style.RESET_ALL}")
    print(f"{'═' * 72}")
    print(f"  Total findings  : {Style.BRIGHT}{len(findings)}{Style.RESET_ALL}  (filtered {fp} false positive(s))")
    print(f"  {Fore.RED}High    : {high}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Medium  : {medium}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Low     : {low}{Style.RESET_ALL}")
    print(f"{'═' * 72}\n")


# ── CLI GROUP ─────────────────────────────────────────────────────────────────
@click.group()
def cli():
    """
    Permi — AI-powered vulnerability scanner.

    Scans code and live web applications for security vulnerabilities
    and uses AI to filter out false positives.

    Built in Nigeria. For Nigeria. Then for the World.
    """
    pass


# ── SCAN COMMAND ──────────────────────────────────────────────────────────────
@cli.command()
@click.option(
    "--url", "-u",
    default=None,
    help="Live URL to scan (e.g. https://yoursite.com). "
         "Performs active HTTP-based vulnerability testing.",
)
@click.option(
    "--path", "-p",
    default=None,
    help="Local directory path or GitHub URL for static code scanning.",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["human", "json"], case_sensitive=False),
    default="human",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["high", "medium", "low", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Minimum severity level to display.",
)
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Skip AI filter and show all raw findings (path scan only).",
)
@click.option(
    "--project",
    default=None,
    help="Project name to store in the database (path scan only).",
)
@click.option(
    "--max-pages",
    default=30,
    show_default=True,
    help="Maximum pages to crawl (URL scan only).",
)
def scan(url, path, output, severity, offline, project, max_pages):
    """
    Scan a live URL or a local/GitHub codebase for vulnerabilities.

    \b
    EXAMPLES

      Scan a live website:
        permi scan --url https://yoursite.com

      Scan a local project:
        permi scan --path ./myapp

      Scan a GitHub repo:
        permi scan --path https://github.com/user/repo

      High severity only:
        permi scan --url https://yoursite.com --severity high

      Export as JSON:
        permi scan --path ./myapp --output json

      Skip AI filter (offline):
        permi scan --path ./myapp --offline

    \b
    SCAN MODES

      --url   Active HTTP scanning — crawls pages, tests SQL injection,
              XSS, and checks security headers on a live website.

      --path  Static source scanning — reads code files, matches
              vulnerability patterns, supports GitHub URL cloning.

    \b
    SEVERITY LEVELS

      high    SQL injection, XSS, hardcoded secrets, eval(), SSL disabled
      medium  Security headers, debug mode, USSD issues
      low     Info disclosure, informational findings
      all     Everything (default)

    \b
    EXIT CODES

      0   No high severity findings
      1   At least one high severity finding (useful for CI/CD pipelines)
    """

    # ── Validate — must provide either --url or --path, not both ─────────────
    if not url and not path:
        click.echo(
            f"\n{Fore.RED}[Error] You must provide either --url or --path.\n\n"
            f"  Examples:\n"
            f"    permi scan --url https://yoursite.com\n"
            f"    permi scan --path ./myproject\n"
            f"    permi scan --path https://github.com/user/repo\n"
            f"{Style.RESET_ALL}"
        )
        sys.exit(1)

    if url and path:
        click.echo(
            f"\n{Fore.RED}[Error] Provide either --url or --path, not both.{Style.RESET_ALL}\n"
        )
        sys.exit(1)

    if output == "human":
        print_banner()

    order = {"high": 1, "medium": 2, "low": 3}

    # ════════════════════════════════════════════════════════════════════
    # MODE A — URL scan (live web scanning)
    # ════════════════════════════════════════════════════════════════════
    if url:
        try:
            # Import here so it doesn't slow down --path-only usage
            from scanner.web_scanner import scan_url
            from ai_filter.filter import run_filter

            # Normalise URL
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            print(f"{Fore.CYAN}[Permi] Mode     : Web scan (active HTTP testing){Style.RESET_ALL}")
            print(f"{Fore.CYAN}[Permi] Target   : {url}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[Permi] Crawl    : up to {max_pages} pages{Style.RESET_ALL}\n")

            # Run web scan
            raw_findings, info = scan_url(url, max_pages=max_pages)
            raw_count = len(raw_findings)

            print(f"\n{Fore.WHITE}[Permi] Engine found {raw_count} raw finding(s){Style.RESET_ALL}\n")

            # Print target info
            if output == "human":
                print_web_info(info)

            # AI filter
            if offline or raw_count == 0:
                if offline:
                    print(f"{Fore.YELLOW}[Permi] Offline mode — AI filter skipped.{Style.RESET_ALL}\n")
                findings = raw_findings
            else:
                findings = run_filter(raw_findings, offline=False)

            # Severity filter
            if severity != "all":
                level = order[severity]
                findings = [
                    f for f in findings
                    if isinstance(f, dict) and order.get(f.get("severity", "low"), 99) <= level
                ]

            # Output
            if output == "json":
                clean = [
                    {k: v for k, v in f.items() if v is not None}
                    for f in findings if isinstance(f, dict)
                ]
                click.echo(json.dumps({"target": url, "info": info, "findings": clean}, indent=2))
            else:
                print_web_results(findings, raw_count)

            if any(f.get("severity") == "high" for f in findings if isinstance(f, dict)):
                sys.exit(1)

        except ImportError as e:
            click.echo(
                f"\n{Fore.RED}[Error] Missing dependencies for web scanning.\n"
                f"Run: pip install httpx beautifulsoup4\n"
                f"Detail: {e}{Style.RESET_ALL}\n"
            )
            sys.exit(1)
        except Exception as e:
            click.echo(f"\n{Fore.RED}[Error] {e}{Style.RESET_ALL}\n")
            sys.exit(1)

    # ════════════════════════════════════════════════════════════════════
    # MODE B — PATH scan (static source code scanning)
    # ════════════════════════════════════════════════════════════════════
    else:
        try:
            findings, raw_count = scan_path(
                path=path,
                project_name=project,
                offline=offline,
            )

            # Severity filter
            if severity != "all":
                level = order[severity]
                findings = [
                    f for f in findings
                    if isinstance(f, dict) and order.get(f.get("severity", "low"), 99) <= level
                ]

            # Output
            if output == "json":
                clean = [
                    {k: v for k, v in f.items() if v is not None}
                    for f in findings if isinstance(f, dict)
                ]
                click.echo(json.dumps(clean, indent=2))
            else:
                print_results_human(findings)
                print_summary(findings, raw_count=raw_count)

            if any(f.get("severity") == "high" for f in findings if isinstance(f, dict)):
                sys.exit(1)

        except FileNotFoundError as e:
            click.echo(f"\n{Fore.RED}[Error] {e}{Style.RESET_ALL}\n")
            sys.exit(1)
        except NotADirectoryError as e:
            click.echo(f"\n{Fore.RED}[Error] {e}{Style.RESET_ALL}\n")
            sys.exit(1)
        except Exception as e:
            click.echo(f"\n{Fore.RED}[Unexpected error] {e}{Style.RESET_ALL}\n")
            sys.exit(1)


cli.add_command(scan, name="scan")
