# cli/main.py
# The Permi command-line interface.
# Every subcommand lives here.
# Entry point is registered in pyproject.toml as 'permi'.

import json
import sys
import click
from colorama import Fore, Style, init

init(autoreset=True)

from cli.formatter import print_banner, print_results_human, print_summary
from scanner.scan import scan


@click.group()
def cli():
    """Permi — AI-powered vulnerability scanner for Nigerian developers."""
    pass


@cli.command()
@click.option(
    "--path", "-p",
    required=True,
    help="Local directory path or GitHub URL to scan."
)
@click.option(
    "--output", "-o",
    type=click.Choice(["human", "json"], case_sensitive=False),
    default="human",
    show_default=True,
    help="Output format."
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["high", "medium", "low", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Minimum severity level to display."
)
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Skip AI filter and show all raw findings."
)
@click.option(
    "--project",
    default=None,
    help="Project name to store in the database."
)
def scan_cmd(path, output, severity, offline, project):
    """
    Scan a local directory or GitHub repo for vulnerabilities.

    Examples:\n
        permi scan --path ./myapp\n
        permi scan --path ./myapp --severity high\n
        permi scan --path ./myapp --output json\n
        permi scan --path ./myapp --offline\n
        permi scan --path https://github.com/user/repo
    """
    if output == "human":
        print_banner()

    try:
        # Run the full scan pipeline
        findings = scan(
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
                if order.get(f["severity"], 99) <= level
            ]

        # ── Output ────────────────────────────────────────────────────────────
        if output == "json":
            clean = [
                {k: v for k, v in f.items() if v is not None}
                for f in findings
            ]
            click.echo(json.dumps(clean, indent=2))

        else:
            print_results_human(findings)
            # raw_count not available here yet — Phase 2 Step 2 improves this
            print_summary(findings, raw_count=len(findings))

        # Exit with code 1 if any high severity findings exist
        # (important for the GitHub Action in Phase 4)
        if any(f["severity"] == "high" for f in findings):
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


# Register 'scan' as the command name
cli.add_command(scan_cmd, name="scan")
