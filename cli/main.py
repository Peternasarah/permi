# cli/main.py  — 
# Permi command-line interface.
#

from __future__ import annotations

import json
import sys
import time
import platform
import importlib.metadata
from pathlib import Path

import click
from colorama import Fore, Style, init

init(autoreset=True)

from cli.formatter import print_results_human, print_summary, print_ai_summary
from cli.feedback  import collect as collect_feedback
from scanner.scan  import scan as scan_path
from cli.exporter  import export as export_results


# ── helpers ───────────────────────────────────────────────────────────────────
def _get_version() -> str:
    try:
        return importlib.metadata.version("permi")
    except Exception:
        return "dev"


def _send_telemetry(findings, raw_count, scan_mode, flags_used, export_fmt, used_community):
    from db.config import is_telemetry_enabled, get_proxy_url
    import requests as req
    if not is_telemetry_enabled():
        return
    try:
        payload = {
            "permi_version":   _get_version(),
            "os_name":         platform.system(),
            "python_version":  f"{sys.version_info.major}.{sys.version_info.minor}",
            "scan_mode":       scan_mode,
            "flags_used":      flags_used,
            "raw_count":       raw_count,
            "real_count":      len(findings),
            "fp_count":        raw_count - len(findings),
            "severity_high":   sum(1 for f in findings if f.get("severity") == "high"),
            "severity_medium": sum(1 for f in findings if f.get("severity") == "medium"),
            "severity_low":    sum(1 for f in findings if f.get("severity") == "low"),
            "rule_ids_fired":  list({f.get("rule_id") for f in findings if f.get("rule_id")}),
            "export_format":   export_fmt,
            "used_community":  used_community,
        }
        req.post(f"{get_proxy_url()}/v1/telemetry", json=payload, timeout=5)
    except Exception:
        pass


# ── banner ────────────────────────────────────────────────────────────────────
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


# ── web scan helpers ──────────────────────────────────────────────────────────
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


# ── FIX 3: UPDATED print_web_finding with UNVERIFIED label ────────────────────
# Rule IDs that are heuristic — shown as UNVERIFIED without AI verdict
_HEURISTIC_RULES = {"WEB_XSS001", "WEB_SQL001", "WEB_SQL002", "WEB_SQL003"}


def print_web_finding(finding: dict, index: int):
    sev     = finding.get("severity", "low")
    rule_id = finding.get("rule_id", "")
    verdict = finding.get("ai_verdict")

    colors = {"high": Fore.RED, "medium": Fore.YELLOW, "low": Fore.CYAN}
    color  = colors.get(sev, Fore.WHITE)

    verdict_colors = {
        "REAL":           Fore.RED,
        "REVIEW":         Fore.YELLOW,
        "FP":             Fore.GREEN,
        "AI_UNAVAILABLE": Fore.YELLOW,
    }
    verdict_labels = {
        "REAL":           "REAL",
        "REVIEW":         "REVIEW — manual check needed",
        "AI_UNAVAILABLE": "AI UNAVAILABLE — review manually",
    }

    # FIX 3: label heuristic findings as UNVERIFIED when no AI has run
    is_unverified = (rule_id in _HEURISTIC_RULES) and (verdict is None)

    if is_unverified:
        sev_label = f"{Fore.YELLOW}[UNVERIFIED]{Style.RESET_ALL}"
    else:
        sev_label = f"{color}{Style.BRIGHT}[{sev.upper()}]{Style.RESET_ALL}"

    print(f"{Fore.WHITE}{'─' * 72}{Style.RESET_ALL}")
    print(
        f"  {Fore.WHITE}{Style.BRIGHT}[{index}]{Style.RESET_ALL} "
        f"{sev_label} "
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

    # FIX 3: show note + upgrade prompt for unverified findings
    if is_unverified:
        print(
            f"  {Fore.YELLOW}Note     : Potential finding — requires AI verification to confirm.{Style.RESET_ALL}\n"
            f"  {Fore.YELLOW}           Run: permi setup --community   (50 free AI credits){Style.RESET_ALL}"
        )

    if verdict:
        vc       = verdict_colors.get(verdict, Fore.WHITE)
        v_label  = verdict_labels.get(verdict, verdict)
        conf     = finding.get("ai_confidence")
        conf_str = f" [{conf}% confidence]" if conf is not None else ""
        print(
            f"  {Fore.WHITE}AI       :{Style.RESET_ALL} "
            f"{vc}{Style.BRIGHT}{v_label}{Style.RESET_ALL}"
            f"{conf_str}  {finding.get('ai_explanation', '')}"
        )
    print()


def print_web_results(findings: list, raw_count: int):
    if raw_count > 0:
        print_ai_summary(findings, raw_count)
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


# ── CLI group ─────────────────────────────────────────────────────────────────
@click.group()
def cli():
    """
    Permi — AI-powered vulnerability scanner.

    Scans live websites and source code for security vulnerabilities,
    then uses AI to filter out false positives.

    Built in Nigeria. For Nigeria. Then for the World.
    """
    pass


# ── scan command ──────────────────────────────────────────────────────────────
@cli.command()
@click.option("--url",  "-u", default=None, help="Live URL to scan (e.g. https://yoursite.com).")
@click.option("--path", "-p", default=None, help="Local directory path or GitHub URL for source code scanning.")
@click.option("--output", "-o", type=click.Choice(["human", "json"], case_sensitive=False),
              default="human", show_default=True, help="Output format.")
@click.option("--severity", "-s", type=click.Choice(["high", "medium", "low", "all"], case_sensitive=False),
              default="all", show_default=True, help="Minimum severity level to display.")
@click.option("--offline", is_flag=True, default=False, help="Skip AI filter and show all raw findings.")
@click.option("--project", default=None, help="Project name to store in the database.")
@click.option("--max-pages", default=30, show_default=True, help="Maximum pages to crawl (URL scan only).")
@click.option("--export", "-e", "export_file", default=None, metavar="FILE",
              help="Export full results to file (.txt, .json, .md).")
@click.option("--include-subdomains", "include_subdomains", is_flag=True, default=False,
              help="Also scan subdomains of the target. External domains are never followed.")
def scan(url, path, output, severity, offline, project,
         max_pages, export_file, include_subdomains):
    """
    Scan a live URL or codebase for vulnerabilities.

    \b
    EXAMPLES

      Scan a live website:
        permi scan --url https://yoursite.com

      Scan including subdomains:
        permi scan --url https://yoursite.com --include-subdomains

      Scan a local project:
        permi scan --path ./myapp

      Scan a GitHub repo:
        permi scan --path https://github.com/user/repo

      High severity only:
        permi scan --url https://yoursite.com --severity high

      Export to file:
        permi scan --path ./myapp --export results.md

      Skip AI filter:
        permi scan --path ./myapp --offline

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

    if output == "human":
        print_banner()

    order    = {"high": 1, "medium": 2, "low": 3}
    has_high = False

    # ════════════════════════════════════════════════════════════════════
    # MODE A — URL scan
    # ════════════════════════════════════════════════════════════════════
    if url:
        try:
            from scanner.web_scanner import scan_url
            from ai_filter.filter    import run_filter
            from db.config           import get_api_key, get_community_token

            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            print(f"{Fore.CYAN}[Permi] Mode     : Web scan (active HTTP testing){Style.RESET_ALL}")
            print(f"{Fore.CYAN}[Permi] Target   : {url}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[Permi] Crawl    : up to {max_pages} pages{Style.RESET_ALL}\n")

            # Scan timer start
            _scan_start = time.time()

            raw_findings, info = scan_url(
                url,
                max_pages=max_pages,
                include_subdomains=include_subdomains,
            )

            # Calculate elapsed time
            _elapsed = time.time() - _scan_start
            _mins    = int(_elapsed // 60)
            _secs    = int(_elapsed % 60)
            _timestr = f"{_mins} min {_secs}s" if _mins > 0 else f"{_secs}s"

            raw_count = len(raw_findings)
            print(f"\n{Fore.WHITE}[Permi] Engine found {raw_count} raw finding(s){Style.RESET_ALL}\n")

            if output == "human":
                print_web_info(info)

            # ── Smart offline mode ─────────────────────────────────────
            if offline:
                # User explicitly asked for raw — give everything
                print(f"{Fore.YELLOW}[Permi] Offline mode — AI filter skipped, showing all findings.{Style.RESET_ALL}\n")
                findings = raw_findings

                

                print(f"{Fore.YELLOW}[Permi] No API key found — running in offline mode.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[Permi] To enable AI filtering run: permi setup --api-key YOUR_KEY{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[Permi] Get a free key at: openrouter.ai{Style.RESET_ALL}\n")

                if needs_ai:
                    print(
                        f"{Fore.CYAN}[Permi] {len(needs_ai)} potential finding(s) require AI verification to confirm.{Style.RESET_ALL}\n"
                        f"{Fore.CYAN}[Permi] XSS and SQL injection results are hidden until AI is enabled.{Style.RESET_ALL}\n"
                        f"{Fore.CYAN}[Permi] Run: permi setup --community   (50 free credits, no card needed){Style.RESET_ALL}\n"
                    )

                # Only return factual high-confidence findings
                findings = high_conf

            else:
                # API key present — full AI filter
                findings = run_filter(raw_findings, offline=False)

            # Severity filter
            if severity != "all":
                level    = order[severity]
                findings = [
                    f for f in findings
                    if isinstance(f, dict) and order.get(f.get("severity", "low"), 99) <= level
                ]

            has_high = any(f.get("severity") == "high" for f in findings if isinstance(f, dict))

            if output == "json":
                clean = [{k: v for k, v in f.items() if v is not None} for f in findings if isinstance(f, dict)]
                click.echo(json.dumps({"target": url, "info": info, "findings": clean}, indent=2))
            else:
                if export_file:
                    print_ai_summary(findings, raw_count)
                    print_summary(findings, raw_count=raw_count)
                else:
                    print_web_results(findings, raw_count)

            # print scan timer
            print(
                f"{Fore.CYAN}  Scan completed in {_timestr} "
                f"| {info.get('urls_tested', 0)} URLs tested{Style.RESET_ALL}\n"
            )

            if export_file and output != "json":
                try:
                    saved = export_results(
                        filepath=export_file,
                        findings=findings,
                        raw_count=raw_count,
                        scan_target=url,
                        info=info,
                    )
                    print(f"\n{Fore.GREEN}[Permi] Full report exported to: {saved}{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}[Permi] Terminal shows summary only — open the file for full details.{Style.RESET_ALL}\n")
                except Exception as e:
                    print(f"\n{Fore.RED}[Permi] Export failed: {e}{Style.RESET_ALL}\n")

            try:
                collect_feedback(scan_target=url, findings_count=len(findings))
            except Exception:
                pass

            if has_high:
                sys.exit(1)

        except ImportError as e:
            click.echo(
                f"\n{Fore.RED}[Error] Missing dependencies for web scanning.\n"
                f"Run: pip install httpx beautifulsoup4\nDetail: {e}{Style.RESET_ALL}\n"
            )
            sys.exit(1)
        except Exception as e:
            click.echo(f"\n{Fore.RED}[Error] {e}{Style.RESET_ALL}\n")
            sys.exit(1)

    # ════════════════════════════════════════════════════════════════════
    # MODE B — PATH scan (unchanged from original)
    # ════════════════════════════════════════════════════════════════════
    else:
        try:
            from db.config import get_api_key, get_community_token

            if not offline and not get_api_key() and not get_community_token():
                print(
                    f"{Fore.YELLOW}[Permi] No API key or community token found — AI filter skipped.\n"
                    f"[Permi] Run: permi setup --community   (50 free credits)\n"
                    f"[Permi] Or:  permi setup --api-key YOUR_KEY{Style.RESET_ALL}\n"
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

            has_high = any(f.get("severity") == "high" for f in findings if isinstance(f, dict))

            if output == "json":
                clean = [{k: v for k, v in f.items() if v is not None} for f in findings if isinstance(f, dict)]
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
                        filepath=export_file,
                        findings=findings,
                        raw_count=raw_count,
                        scan_target=path,
                        info=None,
                    )
                    print(f"\n{Fore.GREEN}[Permi] Full report exported to: {saved}{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}[Permi] Terminal shows summary only — open the file for full details.{Style.RESET_ALL}\n")
                except Exception as e:
                    print(f"\n{Fore.RED}[Permi] Export failed: {e}{Style.RESET_ALL}\n")

            try:
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


# ── setup command (unchanged) ─────────────────────────────────────────────────
@cli.command()
@click.option("--api-key", default=None, help="Your OpenRouter API key.")
@click.option("--community", is_flag=True, default=False, help="Register for 50 free AI credits.")
def setup(api_key, community):
    """Configure Permi — API key or community access."""
    import requests as req
    from db.config import (
        save_api_key, save_community_token, get_config_path, get_proxy_url,
    )

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
                response = req.get(f"{proxy_url}/v1/register", timeout=12)
                response.raise_for_status()
                data      = response.json()
                token     = data["token"]
                remaining = data["credits_remaining"]
                message   = data.get("message", "")

                save_community_token(token)
                registered = True

                click.echo(f" {Fore.GREEN}Connected!{Style.RESET_ALL}")
                click.echo(
                    f"\n{Fore.GREEN}[Permi] ✅  Community access configured!{Style.RESET_ALL}\n"
                    f"\n  Credits    : {Fore.GREEN}{remaining} free AI calls{Style.RESET_ALL}"
                    f"\n  Token      : {token[:8]}...{token[-4:]} (saved to config)\n"
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
                f"[Permi] Check your internet and try again.\n"
                f"[Permi] Or get your own free key: openrouter.ai{Style.RESET_ALL}\n"
            )
        return

    if api_key:
        if not api_key.startswith("sk-"):
            click.echo(
                f"\n{Fore.YELLOW}[Warning] Key does not look like an OpenRouter key "
                f"(expected sk-...). Saving anyway.{Style.RESET_ALL}\n"
            )
        save_api_key(api_key)
        click.echo(
            f"\n{Fore.GREEN}[Permi] ✅  API key saved to: {get_config_path()}{Style.RESET_ALL}\n"
            f"{Fore.WHITE}[Permi] AI filtering is now enabled (unlimited).{Style.RESET_ALL}\n"
            f"{Fore.WHITE}[Permi] Run a scan: permi scan --path ./myapp{Style.RESET_ALL}\n"
        )
        return

    click.echo(
        f"\n{Fore.YELLOW}[Permi] Please provide an option:\n\n"
        f"  Personal API key : permi setup --api-key YOUR_KEY\n"
        f"  Free 50 credits  : permi setup --community\n"
        f"{Style.RESET_ALL}"
    )


# ── info command (unchanged) ──────────────────────────────────────────────────
@cli.command()
def info():
    """Show Permi's configuration status and file locations."""
    import requests as req
    from db.config import (
        get_api_key, get_config_path, get_db_path,
        get_community_token, is_telemetry_enabled, get_proxy_url,
    )

    version = _get_version()
    api_key = get_api_key()

    if api_key:
        key_status = f"{Fore.GREEN}✅  Configured{Style.RESET_ALL}"
        import os
        if os.environ.get("OPENROUTER_API_KEY"):
            key_source = " (from environment variable)"
        elif get_config_path().exists():
            key_source = f" (from {get_config_path()})"
        else:
            key_source = " (from .env file)"
    else:
        key_status = f"{Fore.RED}❌  Not set{Style.RESET_ALL}"
        key_source = ""

    community_token = get_community_token()
    if community_token:
        try:
            r         = req.get(
                f"{get_proxy_url()}/v1/status",
                headers={"X-Permi-Token": community_token},
                timeout=8,
            )
            data      = r.json()
            remaining = data.get("credits_remaining", "?")
            used      = data.get("credits_used", "?")
            total     = data.get("credits_total", 50)
            cr_colour = (
                Fore.GREEN if isinstance(remaining, int) and remaining > 15
                else Fore.YELLOW
            )
            community_status = (
                f"{cr_colour}{remaining}/{total} credits remaining{Style.RESET_ALL} "
                f"({used} used)"
            )
        except Exception:
            community_status = f"{Fore.YELLOW}Token configured (could not fetch status){Style.RESET_ALL}"
    else:
        community_status = (
            f"{Fore.YELLOW}Not configured{Style.RESET_ALL}"
            f" — run: permi setup --community"
        )

    telem_status = (
        f"{Fore.GREEN}enabled{Style.RESET_ALL}"
        if is_telemetry_enabled()
        else f"{Fore.YELLOW}disabled{Style.RESET_ALL} — run: permi setup --telemetry on"
    )

    click.echo(f"""
{Fore.CYAN}{Style.BRIGHT}  Permi — Configuration Info{Style.RESET_ALL}
  {'─' * 56}
  {'Version':<16}: {version}
  {'Database':<16}: {get_db_path()}
  {'Config file':<16}: {get_config_path()}
  {'API key':<16}: {key_status}{key_source}
  {'Community':<16}: {community_status}
  {'Telemetry':<16}: {telem_status}
  {'─' * 56}
  To set API key   : permi setup --api-key YOUR_KEY
  Free 50 credits  : permi setup --community
  To scan a URL    : permi scan --url https://yoursite.com
  To scan code     : permi scan --path ./myapp
  Free API key     : https://openrouter.ai
    """)


# ── feedback command (unchanged) ──────────────────────────────────────────────
@cli.command()
def feedback():
    """Share feedback about Permi."""
    print_banner()
    collect_feedback()


# ── register commands ─────────────────────────────────────────────────────────
cli.add_command(scan,     name="scan")
cli.add_command(setup,    name="setup")
cli.add_command(info,     name="info")
cli.add_command(feedback, name="feedback")
