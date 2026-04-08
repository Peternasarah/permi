# cli/main.py
# Permi command-line interface.
#
# Commands:
#   permi scan  --url  https://target.com    → live web scanner
#   permi scan  --path ./folder              → static source scanner
#   permi setup --api-key sk-or-...          → save API key to ~/.permi/config.json
#   permi info                               → show config paths and status

import json
import sys
import click
from colorama import Fore, Style, init

init(autoreset=True)

from cli.formatter import print_results_human, print_summary
from scanner.scan import scan as scan_path


# ── BANNER ────────────────────────────────────────────────────────────────────
def print_banner():
    print(f"""
{Fore.CYAN}{Style.BRIGHT}  ██████╗ ███████╗██████╗ ███╗   ███╗██╗
  ██╔══██╗██╔════╝██╔══██╗████╗ ████║██║
  ██████╔╝█████╗  ██████╔╝██╔████╔██║██║
  ██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╔╝██║██║
  ██║     ███████╗██║  ██║██║ ╚═╝ ██║██║
  ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝{Style.RESET_ALL}
{Fore.WHITE}{Style.BRIGHT}  AI-Powered Vulnerability Scanner{Style.RESET_ALL}
{Fore.CYAN}  Built in Nigeria. For Nigeria. Then for the World.{Style.RESET_ALL}
{Fore.WHITE}  github.com/Peternasarah/permi  ·  pypi.org/project/permi{Style.RESET_ALL}
""")


def print_web_info(info: dict):
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

    Scans live websites and source code for security vulnerabilities,
    then uses AI to filter out false positives.

    Built in Nigeria. For Nigeria. Then for the World.
    """
    pass


# ── SCAN COMMAND ──────────────────────────────────────────────────────────────
@cli.command()
@click.option("--url",  "-u", default=None,
              help="Live URL to scan (e.g. https://yoursite.com).")
@click.option("--path", "-p", default=None,
              help="Local directory path or GitHub URL for source code scanning.")
@click.option("--output", "-o",
              type=click.Choice(["human", "json"], case_sensitive=False),
              default="human", show_default=True, help="Output format.")
@click.option("--severity", "-s",
              type=click.Choice(["high", "medium", "low", "all"], case_sensitive=False),
              default="all", show_default=True,
              help="Minimum severity level to display.")
@click.option("--offline", is_flag=True, default=False,
              help="Skip AI filter and show all raw findings.")
@click.option("--project", default=None,
              help="Project name to store in the database.")
@click.option("--max-pages", default=30, show_default=True,
              help="Maximum pages to crawl (URL scan only).")
def scan(url, path, output, severity, offline, project, max_pages):
    """
    Scan a live URL or codebase for vulnerabilities.

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

      Skip AI filter:
        permi scan --path ./myapp --offline

    \b
    SCAN MODES

      --url   Active HTTP scanning — crawls the site, tests SQL injection,
              XSS, and checks security headers on a live application.

      --path  Static source scanning — reads code files and detects
              vulnerabilities before they reach production.

    \b
    EXIT CODES

      0   No high severity findings
      1   At least one high severity finding (useful for CI/CD)
    """
    if not url and not path:
        click.echo(
            f"\n{Fore.RED}[Error] Provide either --url or --path.\n\n"
            f"  permi scan --url https://yoursite.com\n"
            f"  permi scan --path ./myproject\n"
            f"  permi scan --path https://github.com/user/repo\n{Style.RESET_ALL}"
        )
        sys.exit(1)

    if url and path:
        click.echo(f"\n{Fore.RED}[Error] Provide either --url or --path, not both.{Style.RESET_ALL}\n")
        sys.exit(1)

    if output == "human":
        print_banner()

    order = {"high": 1, "medium": 2, "low": 3}

    # ════════════════════════════════════════════════════════════════════
    # MODE A — URL scan
    # ════════════════════════════════════════════════════════════════════
    if url:
        try:
            from scanner.web_scanner import scan_url
            from ai_filter.filter import run_filter
            from db.config import get_api_key

            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            print(f"{Fore.CYAN}[Permi] Mode     : Web scan (active HTTP testing){Style.RESET_ALL}")
            print(f"{Fore.CYAN}[Permi] Target   : {url}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[Permi] Crawl    : up to {max_pages} pages{Style.RESET_ALL}\n")

            raw_findings, info = scan_url(url, max_pages=max_pages)
            raw_count = len(raw_findings)

            print(f"\n{Fore.WHITE}[Permi] Engine found {raw_count} raw finding(s){Style.RESET_ALL}\n")

            if output == "human":
                print_web_info(info)

            if offline or raw_count == 0:
                if offline:
                    print(f"{Fore.YELLOW}[Permi] Offline mode — AI filter skipped.{Style.RESET_ALL}\n")
                findings = raw_findings
            else:
                # Check API key and warn if missing
                if not get_api_key():
                    print(
                        f"{Fore.YELLOW}[Permi] No API key found — running in offline mode.\n"
                        f"[Permi] To enable AI filtering run: permi setup --api-key YOUR_KEY\n"
                        f"[Permi] Get a free key at: openrouter.ai{Style.RESET_ALL}\n"
                    )
                findings = run_filter(raw_findings, offline=not get_api_key())

            if severity != "all":
                level    = order[severity]
                findings = [
                    f for f in findings
                    if isinstance(f, dict) and order.get(f.get("severity", "low"), 99) <= level
                ]

            if output == "json":
                clean = [{k: v for k, v in f.items() if v is not None} for f in findings if isinstance(f, dict)]
                click.echo(json.dumps({"target": url, "info": info, "findings": clean}, indent=2))
            else:
                print_web_results(findings, raw_count)

            if any(f.get("severity") == "high" for f in findings if isinstance(f, dict)):
                sys.exit(1)

        except ImportError as e:
            click.echo(f"\n{Fore.RED}[Error] Missing dependencies for web scanning.\nRun: pip install httpx beautifulsoup4\nDetail: {e}{Style.RESET_ALL}\n")
            sys.exit(1)
        except Exception as e:
            click.echo(f"\n{Fore.RED}[Error] {e}{Style.RESET_ALL}\n")
            sys.exit(1)

    # ════════════════════════════════════════════════════════════════════
    # MODE B — PATH scan
    # ════════════════════════════════════════════════════════════════════
    else:
        try:
            from db.config import get_api_key

            # Warn about API key before scan starts
            if not offline and not get_api_key():
                print(
                    f"{Fore.YELLOW}[Permi] No API key found — AI filter will be skipped.\n"
                    f"[Permi] To enable AI filtering run: permi setup --api-key YOUR_KEY\n"
                    f"[Permi] Get a free key at: openrouter.ai{Style.RESET_ALL}\n"
                )
                offline = True

            findings, raw_count = scan_path(
                path=path,
                project_name=project,
                offline=offline,
            )

            if severity != "all":
                level    = order[severity]
                findings = [
                    f for f in findings
                    if isinstance(f, dict) and order.get(f.get("severity", "low"), 99) <= level
                ]

            if output == "json":
                clean = [{k: v for k, v in f.items() if v is not None} for f in findings if isinstance(f, dict)]
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


# ── SETUP COMMAND ─────────────────────────────────────────────────────────────
@cli.command()
@click.option("--api-key", required=True,
              help="Your OpenRouter API key (get one free at openrouter.ai).")
def setup(api_key):
    """
    Save your OpenRouter API key for AI-powered false positive filtering.

    \b
    EXAMPLE
      permi setup --api-key sk-or-your-key-here

    Get a free API key at: https://openrouter.ai
    Your key is saved to ~/.permi/config.json on your machine only.
    It is never sent anywhere except OpenRouter's API.
    """
    from db.config import save_api_key, get_config_path

    if not api_key.startswith("sk-"):
        click.echo(
            f"\n{Fore.YELLOW}[Warning] This key doesn't look like an OpenRouter key "
            f"(expected to start with 'sk-'). Saving anyway.{Style.RESET_ALL}\n"
        )

    save_api_key(api_key)
    config_path = get_config_path()

    click.echo(f"\n{Fore.GREEN}[Permi] ✅  API key saved to: {config_path}{Style.RESET_ALL}")
    click.echo(f"{Fore.WHITE}[Permi] AI false positive filtering is now enabled.{Style.RESET_ALL}")
    click.echo(f"{Fore.WHITE}[Permi] Run a scan: permi scan --path ./myapp{Style.RESET_ALL}\n")


# ── INFO COMMAND ──────────────────────────────────────────────────────────────
@cli.command()
def info():
    """
    Show Permi's configuration status and file locations.

    Useful for checking if your API key is configured correctly
    and where Permi is storing its data.
    """
    from db.config import get_api_key, get_config_path, get_db_path
    import importlib.metadata

    try:
        version = importlib.metadata.version("permi")
    except Exception:
        version = "dev"

    api_key    = get_api_key()
    key_status = f"{Fore.GREEN}✅  Configured{Style.RESET_ALL}" if api_key else f"{Fore.RED}❌  Not set — run: permi setup --api-key YOUR_KEY{Style.RESET_ALL}"
    key_source = ""

    if api_key:
        import os
        from pathlib import Path
        if os.environ.get("OPENROUTER_API_KEY"):
            key_source = " (from environment variable)"
        elif get_config_path().exists():
            key_source = f" (from {get_config_path()})"
        elif (Path.cwd() / ".env").exists():
            key_source = " (from .env file)"

    click.echo(f"""
{Fore.CYAN}{Style.BRIGHT}  Permi — Configuration Info{Style.RESET_ALL}
  {'─' * 50}
  Version     : {version}
  Database    : {get_db_path()}
  Config file : {get_config_path()}
  API key     : {key_status}{key_source}
  {'─' * 50}
  To set API key  : permi setup --api-key YOUR_KEY
  To scan a URL   : permi scan --url https://yoursite.com
  To scan code    : permi scan --path ./myapp
  Free API key    : https://openrouter.ai
    """)


cli.add_command(scan,  name="scan")
cli.add_command(setup, name="setup")
cli.add_command(info,  name="info")
