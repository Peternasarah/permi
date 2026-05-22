# cli/main.py
# Permi command-line interface.
#
# v0.2.17 changes:
#   - All heavy imports moved INSIDE functions (fixes Windows Defender freeze)
#   - _send_telemetry removed (per roadmap decision — proxy logging is sufficient)
#   - setup command cleaned up — telemetry option removed

from __future__ import annotations

import json
import sys
import time
import importlib.metadata
from pathlib import Path

import click
from colorama import Fore, Style, init

init(autoreset=True)


# ── ONLY lightweight imports at module level ──────────────────────────────────
# Heavy imports (scanner, db, ai_filter) are inside the functions that use them.
# This means `permi --help` and `permi info` load instantly without touching
# the filesystem, the database, or any network — fixing the Windows freeze.

def _get_version() -> str:
    try:
        return importlib.metadata.version("permi")
    except Exception:
        return "dev"


# ── BANNER ────────────────────────────────────────────────────────────────────
def print_banner():
    print(f"""
{Fore.CYAN}{Style.BRIGHT}  ██████╗ ███████╗██████╗ ███╗   ███╗██╗
  ██╔══██╗██╔════╝██╔══██╗████╗ ████║██║
  ██████╔╝█████╗  ██████╔╝██╔████╔██║██║
  ██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╔╝██║██║
  ██║     ███████╗██║  ██║██║ ╚═╝ ██║██║
  ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝{Style.RESET_ALL}
{Fore.WHITE}{Style.BRIGHT}  Security Signal Filter for African Fintech Teams{Style.RESET_ALL}
{Fore.CYAN}  Built in Nigeria. For Nigeria. Then for the World.{Style.RESET_ALL}
{Fore.WHITE}  github.com/Peternasarah/permi  ·  pypi.org/project/permi{Style.RESET_ALL}
""")


# ── WEB RESULT HELPERS ────────────────────────────────────────────────────────
def print_web_info(info: dict):
    mode_label = "JS (Playwright)" if info.get("scan_mode") == "js" else "HTTP (fast)"
    print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  TARGET INFORMATION{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
    print(f"  {'Target':<18}: {info.get('target', '—')}")
    print(f"  {'Scan mode':<18}: {mode_label}")
    print(f"  {'IP Address':<18}: {info.get('ip', '—')}")
    print(f"  {'Status Code':<18}: {info.get('status_code', '—')}")
    print(f"  {'Server':<18}: {info.get('server', '—')}")
    print(f"  {'Powered By':<18}: {info.get('powered_by', '—')}")
    print(f"  {'HTTPS':<18}: {'Yes' if info.get('https') else 'No'}")
    print(f"  {'URLs Discovered':<18}: {info.get('urls_discovered', 0)}")
    print(f"  {'URLs Tested':<18}: {info.get('urls_tested', 0)}")
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}\n")


def print_web_finding(finding: dict, index: int):
    sev     = finding.get("severity", "low")
    rule_id = finding.get("rule_id", "")
    verdict = finding.get("ai_verdict")
    colors  = {"high": Fore.RED, "medium": Fore.YELLOW, "low": Fore.CYAN}
    color   = colors.get(sev, Fore.WHITE)
    verdict_colors = {
        "REAL": Fore.RED, "REVIEW": Fore.YELLOW,
        "FP": Fore.GREEN, "AI_UNAVAILABLE": Fore.YELLOW
    }
    verdict_labels = {
        "REAL": "REAL",
        "REVIEW": "REVIEW — manual check needed",
        "AI_UNAVAILABLE": "AI UNAVAILABLE — review manually",
    }
    print(f"{Fore.WHITE}{'─' * 72}{Style.RESET_ALL}")
    print(
        f"  {Fore.WHITE}{Style.BRIGHT}[{index}]{Style.RESET_ALL} "
        f"{color}{Style.BRIGHT}[{sev.upper()}]{Style.RESET_ALL} "
        f"{Fore.WHITE}{Style.BRIGHT}{rule_id}{Style.RESET_ALL}  "
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
    if verdict:
        vc      = verdict_colors.get(verdict, Fore.WHITE)
        vlabel  = verdict_labels.get(verdict, verdict)
        conf    = finding.get("ai_confidence")
        confstr = f" [{conf}% confidence]" if conf is not None else ""
        print(
            f"  {Fore.WHITE}AI       :{Style.RESET_ALL} "
            f"{vc}{Style.BRIGHT}{vlabel}{Style.RESET_ALL}"
            f"{confstr}  {finding.get('ai_explanation', '')}"
        )
    print()


def print_web_results(findings: list, raw_count: int):
    from cli.formatter import print_ai_summary
    if raw_count > 0:
        print_ai_summary(findings, raw_count)
    if not findings:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}  ✅  No vulnerabilities confirmed.\n{Style.RESET_ALL}")
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


def _print_js_upgrade_message():
    """Shown at the END of every JS scan — upgrade prompt, not a warning."""
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  Permi JS — Community Edition limits{Style.RESET_ALL}")
    print(f"  Max pages      : 15 per scan")
    print(f"  Timeout        : configurable via --js-timeout")
    print(f"  Cloudflare     : requires pip install playwright-stealth")
    print()
    print(f"  {Fore.GREEN}Permi Pro (coming soon — ₦5,000/month):{Style.RESET_ALL}")
    print(f"  • Unlimited JS pages")
    print(f"  • Authenticated scanning (pass cookies/session)")
    print(f"  • Advanced Cloudflare bypass")
    print(f"  • Unlimited AI filter credits")
    print(f"  • NDPA compliance rules")
    print()
    print(f"  Join the waitlist: {Fore.CYAN}peternasarah.github.io/permi{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}\n")


# ── CLI GROUP ─────────────────────────────────────────────────────────────────
@click.group()
def cli():
    """Permi — AI-powered vulnerability scanner.\n\nBuilt in Nigeria. For Nigeria. Then for the World."""
    pass


# ── SCAN COMMAND ──────────────────────────────────────────────────────────────
@cli.command()
@click.option("--url",  "-u", default=None, help="Live URL to scan.")
@click.option("--path", "-p", default=None, help="Local directory or GitHub URL for source code.")
@click.option("--output", "-o",
              type=click.Choice(["human", "json"], case_sensitive=False),
              default="human", show_default=True, help="Output format.")
@click.option("--severity", "-s",
              type=click.Choice(["high", "medium", "low", "all"], case_sensitive=False),
              default="all", show_default=True, help="Minimum severity to display.")
@click.option("--offline", is_flag=True, default=False, help="Skip AI filter, show all raw findings.")
@click.option("--project", default=None, help="Project name for the database.")
@click.option("--max-pages", default=30, show_default=True, help="Max pages to crawl.")
@click.option("--export", "-e", "export_file", default=None, metavar="FILE",
              help="Export full results (.txt, .json, .md).")
@click.option("--include-subdomains", "include_subdomains", is_flag=True, default=False,
              help="Also scan subdomains of the target.")
@click.option("--js", "use_js", is_flag=True, default=False,
              help=(
                  "Use Playwright headless browser for JavaScript/SPA sites. "
                  "Requires: pip install playwright && playwright install chromium. "
                  "Optional stealth mode: pip install playwright-stealth"
              ))
@click.option("--js-timeout", "js_timeout", default=20, show_default=True,
              help="Per-page timeout in seconds for --js mode. Default 20s. Cloudflare: 45-60s.")
def scan(url, path, output, severity, offline, project,
         max_pages, export_file, include_subdomains, use_js, js_timeout):
    """
    Scan a live URL or codebase for vulnerabilities.

    \b
    EXAMPLES

      Standard HTTP scan:
        permi scan --url https://yoursite.com

      JavaScript SPA scan (React / Vue / Angular):
        permi scan --url https://yoursite.com --js

      Cloudflare-protected site:
        permi scan --url https://yoursite.com --js --js-timeout 45

      Scan local code:
        permi scan --path ./myapp

      Scan a GitHub repo:
        permi scan --path https://github.com/user/repo

      High severity only:
        permi scan --url https://yoursite.com --severity high

      Export results:
        permi scan --path ./myapp --export results.md

    \b
    EXIT CODES
      0   No high severity findings
      1   At least one high severity finding (useful for CI/CD)
    """
    if not url and not path:
        click.echo(
            f"\n{Fore.RED}[Error] Provide either --url or --path.\n\n"
            f"  permi scan --url https://yoursite.com\n"
            f"  permi scan --path ./myproject\n{Style.RESET_ALL}"
        )
        sys.exit(1)

    if url and path:
        click.echo(f"\n{Fore.RED}[Error] Provide either --url or --path, not both.{Style.RESET_ALL}\n")
        sys.exit(1)

    if use_js and path:
        click.echo(f"\n{Fore.RED}[Error] --js is only for URL scans (--url).{Style.RESET_ALL}\n")
        sys.exit(1)

    if output == "human":
        print_banner()

    order    = {"high": 1, "medium": 2, "low": 3}
    has_high = False

    # ════════════════════════════════════════════════════════════════════
    # MODE A — URL scan
    # ════════════════════════════════════════════════════════════════════
    if url:
        try:
            # All imports inside the function — no module-level freeze risk
            from scanner.web_scanner import scan_url
            from ai_filter.filter    import run_filter
            from cli.formatter       import print_ai_summary, print_summary
            from cli.exporter        import export as export_results
            from db.config           import get_api_key, get_community_token

            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            _t0 = time.time()
            if use_js:
                try:
                    from playwright.async_api import async_playwright  # noqa: F401
                except ImportError:
                    from scanner.js_crawler import print_install_guide
                    print_install_guide()
                    sys.exit(1)
                from scanner.js_crawler import stealth_available, print_stealth_install_hint
                if not stealth_available():
                    print_stealth_install_hint()
                mode_line = f"{Fore.CYAN}[Permi] Mode     : JS scan (Playwright headless browser){Style.RESET_ALL}"
            else:
                mode_line = f"{Fore.CYAN}[Permi] Mode     : Web scan (active HTTP testing){Style.RESET_ALL}"

            print(mode_line)
            print(f"{Fore.CYAN}[Permi] Target   : {url}{Style.RESET_ALL}")

            if use_js:
                print(f"{Fore.CYAN}[Permi] Crawl    : up to {min(max_pages, 15)} pages (JS-rendered){Style.RESET_ALL}")
                print(f"{Fore.CYAN}[Permi] Timeout  : {js_timeout}s per page{Style.RESET_ALL}\n")
            else:
                print(f"{Fore.CYAN}[Permi] Crawl    : up to {max_pages} pages{Style.RESET_ALL}\n")
                
            raw_findings, info = scan_url(
                url,
                max_pages          = max_pages,
                include_subdomains = include_subdomains,
                use_js             = use_js,
                page_timeout_ms    = js_timeout * 1000,
            )

            if not isinstance(raw_findings, list):
                raw_findings = []

            _elapsed = time.time() - _t0
            _mins    = int(_elapsed // 60)
            _secs    = int(_elapsed % 60)
            _timestr = f"{_mins} min {_secs}s" if _mins > 0 else f"{_secs}s"

            raw_count = len(raw_findings)
            print(f"\n{Fore.WHITE}[Permi] Engine found {raw_count} raw finding(s){Style.RESET_ALL}\n")

            if output == "human":
                print_web_info(info)

            if offline:
                print(f"{Fore.YELLOW}[Permi] Offline mode — AI filter skipped.{Style.RESET_ALL}\n")
                findings = raw_findings
            elif raw_count == 0:
                findings = raw_findings
            elif not get_api_key() and not get_community_token():
                print(
                    f"{Fore.YELLOW}[Permi] No API key found.\n"
                    f"[Permi] Run: permi setup --community   (50 free credits)\n"
                    f"[Permi] Or:  permi setup --api-key YOUR_KEY{Style.RESET_ALL}\n"
                )
                findings = raw_findings
            
            else:
                findings = run_filter(raw_findings, offline=False)
                from scanner.intelligence import record_scan
                record_scan(findings, raw_count, scan_mode="url", duration_seconds=int(time.time() - _t0))

            if severity != "all":
                level    = order[severity]
                findings = [
                    f for f in findings
                    if isinstance(f, dict)
                    and order.get(f.get("severity", "low"), 99) <= level
                ]

            has_high = any(
                f.get("severity") == "high" for f in findings if isinstance(f, dict)
            )

            if output == "json":
                clean = [
                    {k: v for k, v in f.items() if v is not None}
                    for f in findings if isinstance(f, dict)
                ]
                click.echo(json.dumps({"target": url, "info": info, "findings": clean}, indent=2))
            else:
                if export_file:
                    print_ai_summary(findings, raw_count)
                    print_summary(findings, raw_count=raw_count)
                else:
                    print_web_results(findings, raw_count)

            print(f"{Fore.CYAN}  Scan completed in {_timestr} | {info.get('urls_tested', 0)} URLs tested{Style.RESET_ALL}\n")

            if use_js and output == "human":
                _print_js_upgrade_message()

            if export_file and output != "json":
                try:
                    saved = export_results(
                        filepath=export_file, findings=findings,
                        raw_count=raw_count, scan_target=url, info=info,
                    )
                    print(f"\n{Fore.GREEN}[Permi] Report exported to: {saved}{Style.RESET_ALL}\n")
                except Exception as e:
                    print(f"\n{Fore.RED}[Permi] Export failed: {e}{Style.RESET_ALL}\n")

            try:
                from cli.feedback import collect as collect_feedback
                collect_feedback(scan_target=url, findings_count=len(findings))
            except Exception:
                pass

            if has_high:
                sys.exit(1)

        except ImportError as e:
            click.echo(
                f"\n{Fore.RED}[Error] Missing dependencies.\n"
                f"Run: pip install httpx beautifulsoup4\nDetail: {e}{Style.RESET_ALL}\n"
            )
            sys.exit(1)
        except Exception as e:
            click.echo(f"\n{Fore.RED}[Error] {e}{Style.RESET_ALL}\n")
            sys.exit(1)

    # ════════════════════════════════════════════════════════════════════
    # MODE B — PATH scan
    # ════════════════════════════════════════════════════════════════════
    else:
        try:
            # All imports inside function — no module-level freeze risk
            from scanner.scan    import scan as scan_path
            from cli.formatter   import print_results_human, print_summary, print_ai_summary
            from cli.exporter    import export as export_results
            from db.config       import get_api_key, get_community_token

            if not offline and not get_api_key() and not get_community_token():
                print(
                    f"{Fore.YELLOW}[Permi] No API key found — AI filter skipped.\n"
                    f"[Permi] Run: permi setup --community   (50 free credits)\n"
                    f"[Permi] Or:  permi setup --api-key YOUR_KEY{Style.RESET_ALL}\n"
                )
                offline = True

            _t0 = time.time()
            findings, raw_count = scan_path(
                path=path, project_name=project, offline=offline,
            )            

            try:
                from scanner.intelligence import record_scan
                record_scan(findings, raw_count, scan_mode="path", duration_seconds=int(time.time() - _t0))
            except Exception:
                pass

            if severity != "all":
                level    = order[severity]
                findings = [
                    f for f in findings
                    if isinstance(f, dict)
                    and order.get(f.get("severity", "low"), 99) <= level
                ]

            has_high = any(
                f.get("severity") == "high" for f in findings if isinstance(f, dict)
            )

            if output == "json":
                clean = [
                    {k: v for k, v in f.items() if v is not None}
                    for f in findings if isinstance(f, dict)
                ]
                click.echo(json.dumps(clean, indent=2))
            else:
                if export_file:
                    print_ai_summary(findings, raw_count)
                    print_summary(findings, raw_count=raw_count)
                else:
                    print_results_human(findings, raw_count=raw_count)
                    print_summary(findings, raw_count=raw_count)

            if export_file and output != "json":
                try:
                    saved = export_results(
                        filepath=export_file, findings=findings,
                        raw_count=raw_count, scan_target=path, info=None,
                    )
                    print(f"\n{Fore.GREEN}[Permi] Report exported to: {saved}{Style.RESET_ALL}\n")
                except Exception as e:
                    print(f"\n{Fore.RED}[Permi] Export failed: {e}{Style.RESET_ALL}\n")

            try:
                from cli.feedback import collect as collect_feedback
                collect_feedback(scan_target=path, findings_count=len(findings))
            except Exception:
                pass

            if has_high:
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
@click.option("--api-key",    default=None,         help="Your OpenRouter API key.")
@click.option("--community",  is_flag=True, default=False, help="Register for 50 free AI credits.")
def setup(api_key, community):
    """
    Configure Permi — API key or community access.

    \b
    EXAMPLES
      Personal API key (unlimited):
        permi setup --api-key sk-or-your-key-here

      Free community credits (50 calls, no key needed):
        permi setup --community
    """
    import requests as req
    # Import inside function to avoid freeze
    from db.config import save_api_key, save_community_token, get_config_path, get_proxy_url

    if community:
        proxy_url  = get_proxy_url()
        max_wait   = 90
        interval   = 8
        attempts   = max_wait // interval
        registered = False

        click.echo(
            f"\n{Fore.CYAN}[Permi] Connecting to community proxy...\n"
            f"[Permi] Render may need up to 60s to wake — retrying automatically.{Style.RESET_ALL}\n"
        )

        for attempt in range(1, attempts + 1):
            try:
                click.echo(f"  Attempt {attempt}/{attempts}...", nl=False)
                r = req.get(f"{proxy_url}/v1/register", timeout=12)
                r.raise_for_status()
                data      = r.json()
                token     = data["token"]
                remaining = data["credits_remaining"]
                message   = data.get("message", "")
                save_community_token(token)
                registered = True
                click.echo(f" {Fore.GREEN}Connected!{Style.RESET_ALL}")
                click.echo(
                    f"\n{Fore.GREEN}[Permi] ✅  Community access configured!{Style.RESET_ALL}\n"
                    f"\n  Credits : {Fore.GREEN}{remaining} free AI calls{Style.RESET_ALL}"
                    f"\n  Token   : {token[:8]}...{token[-4:]} (saved)\n"
                )
                if message:
                    click.echo(f"  {Fore.CYAN}{message}{Style.RESET_ALL}\n")
                click.echo(
                    f"{Fore.WHITE}[Permi] Run a scan     : permi scan --path ./myapp{Style.RESET_ALL}\n"
                    f"{Fore.WHITE}[Permi] Upgrade later  : permi setup --api-key YOUR_KEY{Style.RESET_ALL}\n"
                )
                break
            except req.exceptions.Timeout:
                click.echo(f" {Fore.YELLOW}timeout, retrying...{Style.RESET_ALL}")
            except req.exceptions.ConnectionError:
                click.echo(f" {Fore.YELLOW}connection error, retrying...{Style.RESET_ALL}")
            except Exception as e:
                click.echo(f" {Fore.RED}failed ({e}){Style.RESET_ALL}")
            if attempt < attempts:
                time.sleep(interval)

        if not registered:
            click.echo(
                f"\n{Fore.RED}[Permi] Could not reach proxy after {max_wait}s.\n"
                f"[Permi] Check your internet connection and try again.\n"
                f"[Permi] Or get your own free key: openrouter.ai{Style.RESET_ALL}\n"
            )
        return

    if api_key:
        if not api_key.startswith("sk-"):
            click.echo(
                f"\n{Fore.YELLOW}[Warning] Key does not look like an OpenRouter key (expected sk-...). "
                f"Saving anyway.{Style.RESET_ALL}\n"
            )
        save_api_key(api_key)
        click.echo(
            f"\n{Fore.GREEN}[Permi] ✅  API key saved to: {get_config_path()}{Style.RESET_ALL}\n"
            f"{Fore.WHITE}[Permi] AI filtering enabled (unlimited). Run: permi scan --path ./myapp{Style.RESET_ALL}\n"
        )
        return

    click.echo(
        f"\n{Fore.YELLOW}[Permi] Please provide an option:\n\n"
        f"  Personal API key : permi setup --api-key YOUR_KEY\n"
        f"  Free 50 credits  : permi setup --community\n"
        f"{Style.RESET_ALL}"
    )


# ── INFO COMMAND ──────────────────────────────────────────────────────────────
@cli.command()
def info():
    """Show Permi configuration, credits, and Playwright status."""
    import requests as req
    # Import inside function to avoid freeze
    from db.config import get_api_key, get_config_path, get_db_path, get_community_token, get_proxy_url
    import os

    version = _get_version()
    api_key = get_api_key()

    if api_key:
        key_status = f"{Fore.GREEN}✅  Configured{Style.RESET_ALL}"
        key_source = (
            " (from environment variable)" if os.environ.get("OPENROUTER_API_KEY")
            else (f" (from {get_config_path()})" if get_config_path().exists() else " (from .env file)")
        )
    else:
        key_status = f"{Fore.RED}❌  Not set{Style.RESET_ALL}"
        key_source = ""

    community_token = get_community_token()
    if community_token:
        try:
            r    = req.get(
                f"{get_proxy_url()}/v1/status",
                headers={"X-Permi-Token": community_token},
                timeout=8,
            )
            data      = r.json()
            remaining = data.get("credits_remaining", "?")
            used      = data.get("credits_used", "?")
            total     = data.get("credits_total", 50)
            cr_colour = Fore.GREEN if isinstance(remaining, int) and remaining > 15 else Fore.YELLOW
            community_status = (
                f"{cr_colour}{remaining}/{total} credits remaining{Style.RESET_ALL} ({used} used)"
            )
        except Exception:
            community_status = f"{Fore.YELLOW}Token configured (could not fetch status){Style.RESET_ALL}"
    else:
        community_status = f"{Fore.YELLOW}Not configured{Style.RESET_ALL} — run: permi setup --community"

    try:
        from playwright.async_api import async_playwright  # noqa: F401
        pw_status = f"{Fore.GREEN}✅  Installed{Style.RESET_ALL}"
    except ImportError:
        pw_status = f"{Fore.RED}❌  Not installed{Style.RESET_ALL} — pip install playwright && playwright install chromium"

    try:
        from playwright_stealth import Stealth  # noqa: F401
        stealth_status = f"{Fore.GREEN}✅  Installed (Cloudflare bypass active){Style.RESET_ALL}"
    except ImportError:
        stealth_status = f"{Fore.YELLOW}Not installed{Style.RESET_ALL} — pip install playwright-stealth"

    click.echo(f"""
{Fore.CYAN}{Style.BRIGHT}  Permi — Configuration Info{Style.RESET_ALL}
  {'─' * 64}
  {'Version':<22}: {version}
  {'Database':<22}: {get_db_path()}
  {'Config file':<22}: {get_config_path()}
  {'API key':<22}: {key_status}{key_source}
  {'Community':<22}: {community_status}
  {'Playwright (--js)':<22}: {pw_status}
  {'Stealth (Cloudflare)':<22}: {stealth_status}
  {'─' * 64}
  Standard scan      : permi scan --url https://yoursite.com
  JS/SPA scan        : permi scan --url https://yoursite.com --js
  Cloudflare site    : permi scan --url https://yoursite.com --js --js-timeout 45
  Scan code          : permi scan --path ./myapp
  Free API key       : https://openrouter.ai
    """)

@cli.command()
def stats():
    """Show your accumulated scan intelligence — which rules fire most, what frameworks you scan, how accurate the filter is."""
    from scanner.intelligence import get_local_stats, get_rule_precision_report

    data = get_local_stats()

    if not data or data.get("total_scans", 0) == 0:
        click.echo(
            f"\n{Fore.YELLOW}[Permi] No scan data yet.\n"
            f"[Permi] Run a few scans and come back.{Style.RESET_ALL}\n"
        )
        return

    scans  = data.get("total_scans", 0)
    raw    = data.get("total_raw", 0)
    real   = data.get("total_confirmed", 0)
    fp     = data.get("total_fp", 0)
    noise  = data.get("overall_noise_reduction", 0)

    click.echo(f"""
{Fore.CYAN}{Style.BRIGHT}  Permi — Your Scan Intelligence{Style.RESET_ALL}
  {Fore.WHITE}Data is stored locally in ~/.permi/intelligence.db{Style.RESET_ALL}
  {'─' * 60}
  {'Total scans run':<28}: {scans}
  {'Raw findings total':<28}: {raw}
  {'Confirmed real findings':<28}: {real}
  {'False positives removed':<28}: {fp}
  {'Overall noise reduction':<28}: {Fore.GREEN}{noise}%{Style.RESET_ALL}
  {'─' * 60}""")

    # Top rules
    top_rules = data.get("top_rules", [])
    if top_rules:
        click.echo(f"\n  {Fore.WHITE}{Style.BRIGHT}Rules firing most often:{Style.RESET_ALL}")
        for r in top_rules[:7]:
            prec_color = (
                Fore.GREEN if r["precision"] >= 80
                else Fore.YELLOW if r["precision"] >= 50
                else Fore.RED
            )
            click.echo(
                f"    {r['rule_id']:<12} "
                f"{r['total']:>4} fires  "
                f"{prec_color}{r['precision']:>5.1f}% precision{Style.RESET_ALL}"
                f"  ({r['real']} real, {r['fp']} FP)"
            )

    # Frameworks
    frameworks = data.get("top_frameworks", [])
    if frameworks:
        fw_str = ", ".join(f"{f['name']} ({f['count']})" for f in frameworks[:6])
        click.echo(f"\n  {Fore.WHITE}{Style.BRIGHT}Frameworks scanned:{Style.RESET_ALL} {fw_str}")

    # Payment APIs
    apis = data.get("payment_apis", [])
    if apis:
        click.echo(f"\n  {Fore.WHITE}{Style.BRIGHT}Payment APIs encountered:{Style.RESET_ALL}")
        for a in apis:
            exp_str = (
                f"  {Fore.RED}⚠️  {a['exposed']} times with exposed credentials{Style.RESET_ALL}"
                if a["exposed"] > 0 else ""
            )
            click.echo(f"    {a['name']:<16} seen in {a['scanned']} scan(s){exp_str}")

    # Low precision rules (improvement candidates)
    precision_report = get_rule_precision_report()
    low_precision    = [r for r in precision_report if r.get("precision", 100) < 60 and r.get("fires_total", 0) >= 5]
    if low_precision:
        click.echo(f"\n  {Fore.YELLOW}{Style.BRIGHT}Rules with low precision (candidate for improvement):{Style.RESET_ALL}")
        for r in low_precision[:3]:
            click.echo(
                f"    {Fore.YELLOW}{r['rule_id']}{Style.RESET_ALL} — "
                f"{r['precision']:.1f}% precision over {r['fires_total']} fires"
            )
        click.echo(f"\n  {Fore.WHITE}Consider opening an issue: github.com/Peternasarah/permi/issues{Style.RESET_ALL}")

    click.echo(f"""
  {'─' * 60}
  {Fore.WHITE}This data is stored only on your machine.{Style.RESET_ALL}
  {Fore.WHITE}Nothing is shared without your explicit consent.{Style.RESET_ALL}
  {Fore.WHITE}To delete it: del C:\\Users\\<you>\\.permi\\intelligence.db{Style.RESET_ALL}
    """)

# ── FEEDBACK COMMAND ──────────────────────────────────────────────────────────
@cli.command()
def feedback():
    """Share feedback about Permi."""
    from cli.feedback import collect as collect_feedback
    print_banner()
    collect_feedback()


# ── REGISTER ──────────────────────────────────────────────────────────────────
cli.add_command(scan,     name="scan")
cli.add_command(setup,    name="setup")
cli.add_command(info,     name="info")
cli.add_command(feedback, name="feedback")
cli.add_command(stats, name="stats")
