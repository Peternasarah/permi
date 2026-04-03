# cli/main.py
import json
import sys
import click
from colorama import Fore, Style, init

init(autoreset=True)

from cli.formatter import print_banner, print_results_human, print_summary
from scanner.scan import scan


@click.group()
def cli():
    """
    Permi — AI-powered vulnerability scanner.

    Scans code for vulnerabilities and uses AI to filter out false
    positives so you only see findings that actually matter.

    Built in Nigeria. For Nigeria. Then for the world.
    """
    pass


@cli.command()
@click.option("--path", "-p", required=True,
              help="Local directory path or GitHub URL to scan.")
@click.option("--output", "-o",
              type=click.Choice(["human", "json"], case_sensitive=False),
              default="human", show_default=True,
              help="Output format.")
@click.option("--severity", "-s",
              type=click.Choice(["high", "medium", "low", "all"], case_sensitive=False),
              default="all", show_default=True,
              help="Minimum severity level to display.")
@click.option("--offline", is_flag=True, default=False,
              help="Skip AI filter and show all raw findings.")
@click.option("--project", default=None,
              help="Project name to store in the database.")
def scan_cmd(path, output, severity, offline, project):
    """
    Scan a local directory or GitHub repo for vulnerabilities.

    Permi detects SQL injection, XSS, hardcoded secrets, insecure
    practices, and USSD vulnerabilities. An AI filter then removes
    false positives so only real issues are shown.

    \b
    EXAMPLES

      Scan a local project:
        permi scan --path ./myapp

      Scan a GitHub repo:
        permi scan --path https://github.com/user/repo

      High severity only:
        permi scan --path ./myapp --severity high

      Export as JSON for CI/CD:
        permi scan --path ./myapp --output json

      Skip AI filter (no API key needed):
        permi scan --path ./myapp --offline

      Name your project in the database:
        permi scan --path ./myapp --project my-api

    \b
    SEVERITY LEVELS

      high    — SQL injection, hardcoded secrets, eval(), XSS, SSL disabled
      medium  — debug mode, USSD input issues
      low     — informational findings
      all     — everything (default)

    \b
    EXIT CODES

      0   No high severity findings
      1   At least one high severity finding (useful for CI/CD pipelines)
    """
    if output == "human":
        print_banner()

    try:
        # Run the full scan pipeline
        findings, raw_count = scan(
            path=path,
            project_name=project,
            offline=offline,
        )

        # ── Severity filter ───────────────────────────────────────────────────
        order = {"high": 1, "medium": 2, "low": 3}

        if severity != "all":
            level = order[severity]
            findings = [
                f for f in findings
                if isinstance(f, dict) and order.get(f.get("severity", "low"), 99) <= level
            ]

        # ── Output ────────────────────────────────────────────────────────────
        if output == "json":
            clean = [
                {k: v for k, v in f.items() if v is not None}
                for f in findings
                if isinstance(f, dict)
            ]
            click.echo(json.dumps(clean, indent=2))

        else:
            print_results_human(findings)
            print_summary(findings, raw_count=raw_count)

        # Exit code 1 if any high severity findings — used by GitHub Action
        if any(f.get("severity") == "high" for f in findings if isinstance(f, dict)):
            sys.exit(1)

    except FileNotFoundError as e:
        click.echo(Fore.RED + f"\n[Error] {e}\n")
        sys.exit(1)
    except NotADirectoryError as e:
        click.echo(Fore.RED + f"\n[Error] {e}\n")
        sys.exit(1)
    except Exception as e:
        click.echo(Fore.RED + f"\n[Unexpected error] {e}\n")
        sys.exit(1)


cli.add_command(scan_cmd, name="scan")
