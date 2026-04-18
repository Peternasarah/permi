# cli/feedback.py
# Permi feedback collector.
# Submits to Google Forms silently — no browser needed.
# Also saves a local copy to ~/.permi/feedback.json as backup.

from __future__ import annotations

import json
import time
import urllib.request
import urllib.parse
from datetime import datetime
from pathlib import Path

from colorama import Fore, Style

# ── Google Form config ────────────────────────────────────────────────────────
FORM_ID = "1FAIpQLSeKTGYaoIjFRZOOn1lPAZ2t2naD_1cHwnLDXZDOc8yJ-BVZhw"

ENTRY_RATING   = "entry.1453670559"   # How useful was this scan? (1-5)
ENTRY_MISS     = "entry.1118711712"   # What did Permi miss or get wrong?
ENTRY_FEATURE  = "entry.1369535742"   # What feature would make you use Permi every day?
ENTRY_EMAIL    = "entry.481202435"    # Email (optional)

FORM_URL = f"https://docs.google.com/forms/d/e/{FORM_ID}/formResponse"

# ── Local storage ─────────────────────────────────────────────────────────────
FEEDBACK_FILE = Path.home() / ".permi" / "feedback.json"


def _save_locally(data: dict) -> None:
    """Save feedback entry to ~/.permi/feedback.json."""
    try:
        FEEDBACK_FILE.parent.mkdir(parents=True, exist_ok=True)
        existing = []
        if FEEDBACK_FILE.exists():
            try:
                existing = json.loads(FEEDBACK_FILE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                existing = []
        existing.append(data)
        FEEDBACK_FILE.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    except Exception:
        pass  # Never crash because of feedback saving


def _submit_to_google(rating: str, miss: str, feature: str, email: str) -> bool:
    """
    Submit feedback to Google Forms silently.
    Retries up to 10 times with exponential backoff.
    Returns True if any attempt succeeded, False if all failed.
    """
    params = {ENTRY_RATING: rating}
    if miss.strip():
        params[ENTRY_MISS] = miss.strip()
    if feature.strip():
        params[ENTRY_FEATURE] = feature.strip()
    if email.strip():
        params[ENTRY_EMAIL] = email.strip()

    data = urllib.parse.urlencode(params).encode("utf-8")

    MAX_ATTEMPTS = 10

    for attempt in range(MAX_ATTEMPTS):
        try:
            req = urllib.request.Request(
                FORM_URL,
                data=data,
                method="POST",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent":   "Permi-CLI-Feedback/1.0",
                }
            )
            urllib.request.urlopen(req, timeout=8)
            return True  # success — stop retrying

        except Exception:
            if attempt < MAX_ATTEMPTS - 1:
                # Exponential backoff: 1s, 2s, 4s, 8s, 16s... capped at 30s
                wait = min(2 ** attempt, 30)
                time.sleep(wait)
            continue

    return False  # all 10 attempts failed


def collect(scan_target: str = "", findings_count: int = 0) -> None:
    """
    Interactive feedback prompt shown after a scan.
    Skippable — pressing Enter on any question skips it.
    Pressing Enter on the rating question skips the entire form.
    """
    print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  Quick feedback — help shape Permi{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Press Enter on any question to skip it.{Style.RESET_ALL}\n")

    # ── Rating ────────────────────────────────────────────────────────────────
    while True:
        rating_raw = input(
            f"  {Fore.WHITE}How useful was this scan? {Fore.CYAN}[1–5]{Style.RESET_ALL}"
            f" {Fore.WHITE}(Enter to skip):{Style.RESET_ALL} "
        ).strip()

        if not rating_raw:
            # User skipped — don't collect anything
            print(f"\n  {Fore.YELLOW}Feedback skipped. That's fine!{Style.RESET_ALL}\n")
            return

        if rating_raw in ("1", "2", "3", "4", "5"):
            break

        print(f"  {Fore.YELLOW}Please enter a number between 1 and 5.{Style.RESET_ALL}")

    # ── What did Permi miss ───────────────────────────────────────────────────
    miss = input(
        f"  {Fore.WHITE}What did Permi miss or get wrong?{Style.RESET_ALL}"
        f" {Fore.WHITE}(Enter to skip):{Style.RESET_ALL} "
    )

    # ── Feature request ───────────────────────────────────────────────────────
    feature = input(
        f"  {Fore.WHITE}What feature would make you use Permi every day?{Style.RESET_ALL}"
        f" {Fore.WHITE}(Enter to skip):{Style.RESET_ALL} "
    )

    # ── Email (optional) ──────────────────────────────────────────────────────
    email = input(
        f"  {Fore.WHITE}Your email{Style.RESET_ALL}"
        f" {Fore.CYAN}(optional — for follow-up):{Style.RESET_ALL} "
    )

    # ── Save locally ──────────────────────────────────────────────────────────
    entry = {
        "timestamp":      datetime.now().isoformat(),
        "rating":         rating_raw,
        "miss":           miss.strip(),
        "feature":        feature.strip(),
        "email":          email.strip(),
        "scan_target":    scan_target,
        "findings_count": findings_count,
    }
    _save_locally(entry)

    # ── Submit to Google Forms ────────────────────────────────────────────────
    print(f"\n  {Fore.CYAN}Submitting...{Style.RESET_ALL}", end="", flush=True)
    success = _submit_to_google(rating_raw, miss, feature, email)

    if success:
        print(
            f"\r  {Fore.GREEN}✅  Thank you! Your feedback helps build "
            f"Permi for Nigerian developers.{Style.RESET_ALL}"
        )
    else:
        print(
            f"\r  {Fore.YELLOW}⚠️   Could not reach the server — "
            f"feedback saved locally.{Style.RESET_ALL}"
        )

    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}\n")
