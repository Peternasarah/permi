# ai_filter/llm_client.py
# The only module in Permi that makes network requests.
# Sends a finding to OpenRouter and returns a verdict:
#   REAL  — this is a genuine vulnerability
#   FP    — this is a false positive, ignore it
#
# API key is loaded via db/config.py priority chain.
# Retry logic handles intermittent SSL EOF errors from OpenRouter.
# If all retries fail, verdict is marked AI_UNAVAILABLE — never fakes REAL.

from __future__ import annotations

import os
import json
import time
import requests
from db.config import get_api_key

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Configurable via environment variable — future-proof if model changes
MODEL   = os.environ.get("PERMI_LLM_MODEL", "deepseek/deepseek-chat")
TIMEOUT = 30

# How many times to retry on SSL/network errors before giving up
MAX_RETRIES = 3


def _build_prompt(finding: dict) -> str:
    return f"""You are a senior application security engineer reviewing automated scan results.

A static analysis tool flagged the following finding. Your job is to decide if this is a REAL vulnerability or a FALSE POSITIVE (FP).

--- FINDING ---
Rule     : {finding['rule_id']} — {finding['rule_name']}
Severity : {finding['severity']}
File     : {finding['file']}
Line     : {finding['line_number']}
Code     : {finding['line_content']}
Detail   : {finding['description']}
---------------

Instructions:
- Answer with exactly one word on the first line: REAL or FP
- On the second line, write one short sentence (max 20 words) explaining your verdict
- Do not write anything else

Your verdict:"""


def _is_ssl_eof_error(error: Exception) -> bool:
    """Return True if the error is the common OpenRouter SSL EOF issue."""
    msg = str(error)
    return (
        "UNEXPECTED_EOF_WHILE_READING" in msg
        or "EOF occurred in violation of protocol" in msg
        or "SSLEOFError" in msg
        or "Connection reset by peer" in msg
    )


def analyse(finding: dict) -> dict:
    """
    Send one finding to the LLM and return the finding dict
    updated with ai_verdict and ai_explanation.

    Retry logic:
      - SSL EOF errors → retry up to MAX_RETRIES times with backoff
      - Other network errors → fail immediately, mark as AI_UNAVAILABLE
      - AI_UNAVAILABLE findings are kept in output but clearly labelled
        (never silently promoted to REAL)
    """
    api_key = get_api_key()

    if not api_key:
        finding["ai_verdict"]     = "REAL"
        finding["ai_explanation"] = "No API key — AI filter skipped."
        return finding

    prompt = _build_prompt(finding)
    last_error = ""

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(
                OPENROUTER_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type":  "application/json",
                    "HTTP-Referer":  "https://github.com/Peternasarah/permi",
                    "X-Title":       "Permi Security Scanner",
                },
                json={
                    "model":       MODEL,
                    "messages":    [{"role": "user", "content": prompt}],
                    "temperature": 0,
                    "max_tokens":  60,
                },
                timeout=TIMEOUT,
            )
            response.raise_for_status()

            # ── Parse response ────────────────────────────────────────────────
            content     = response.json()["choices"][0]["message"]["content"].strip()
            lines       = content.splitlines()
            verdict     = lines[0].strip().upper()
            explanation = lines[1].strip() if len(lines) > 1 else "No explanation provided."

            if verdict not in ("REAL", "FP"):
                invalid_verdict = verdict
                verdict         = "REAL"
                explanation     = f"Unexpected model verdict '{invalid_verdict}' — defaulting to REAL."

            finding["ai_verdict"]     = verdict
            finding["ai_explanation"] = explanation
            return finding

        except requests.exceptions.Timeout:
            # Timeout — retry
            last_error = "request timed out"
            wait = (2 ** attempt) * 1.5
            if attempt < MAX_RETRIES - 1:
                time.sleep(wait)
            continue

        except requests.exceptions.RequestException as exc:
            if _is_ssl_eof_error(exc):
                # SSL EOF — common OpenRouter glitch, retry with backoff
                last_error = "SSL connection error"
                wait = (2 ** attempt) * 1.5
                if attempt < MAX_RETRIES - 1:
                    time.sleep(wait)
                continue
            else:
                # Other network error — don't retry
                last_error = "network error"
                break

        except (KeyError, IndexError, json.JSONDecodeError):
            # Bad response format — don't retry
            last_error = "unexpected response format"
            break

    # ── All retries exhausted or unrecoverable error ──────────────────────────
    # Mark as AI_UNAVAILABLE — do NOT silently promote to REAL.
    # The finding will still appear in output but clearly labelled.
    finding["ai_verdict"]     = "AI_UNAVAILABLE"
    finding["ai_explanation"] = f"AI filter unavailable ({last_error}) — review manually."
    return finding
