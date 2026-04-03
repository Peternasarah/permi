# ai_filter/llm_client.py
# The only module in Permi that makes network requests.
# Sends a finding to OpenRouter and returns a verdict:
#   REAL  — this is a genuine vulnerability
#   FP    — this is a false positive, ignore it

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_URL     = "https://openrouter.ai/api/v1/chat/completions"

# We use DeepSeek V3 — fast, cheap, and very good at code analysis.
# You can swap this for any model on openrouter.ai/models
MODEL = "deepseek/deepseek-chat"

# How many seconds to wait for the API before giving up
TIMEOUT = 30


def _build_prompt(finding: dict) -> str:
    """
    Build the prompt we send to the LLM for a single finding.
    The prompt is structured so the model returns a predictable format
    we can parse reliably.
    """
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

Example response:
REAL
The string concatenation directly embeds user input into a SQL query with no sanitisation.

Your verdict:"""


def analyse(finding: dict) -> dict:
    """
    Send one finding to the LLM and return the finding dict
    updated with ai_verdict and ai_explanation.

    If the API call fails for any reason (no key, network error,
    bad response), we default to REAL so nothing gets silently dropped.
    """
    # If no API key is configured, skip the filter entirely
    if not OPENROUTER_API_KEY:
        finding["ai_verdict"]     = "REAL"
        finding["ai_explanation"] = "No API key — AI filter skipped."
        return finding

    prompt = _build_prompt(finding)

    try:
        response = requests.post(
            OPENROUTER_URL,
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type":  "application/json",
                "HTTP-Referer":  "https://github.com/permi",   # required by OpenRouter
                "X-Title":       "Permi Security Scanner",
            },
            json={
                "model": MODEL,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0,     # we want deterministic, not creative
                "max_tokens":  60,    # verdict + one sentence is plenty
            },
            timeout=TIMEOUT,
        )
        response.raise_for_status()

    except requests.exceptions.Timeout:
        finding["ai_verdict"]     = "REAL"
        finding["ai_explanation"] = "API timeout — defaulting to REAL."
        return finding

    except requests.exceptions.RequestException as e:
        finding["ai_verdict"]     = "REAL"
        finding["ai_explanation"] = f"API error — defaulting to REAL. ({e})"
        return finding

    # ── Parse the response ────────────────────────────────────────────────────
    try:
        content = response.json()["choices"][0]["message"]["content"].strip()
        lines   = content.splitlines()

        verdict     = lines[0].strip().upper()
        explanation = lines[1].strip() if len(lines) > 1 else "No explanation provided."

        # Normalise — if the model returns anything unexpected, treat as REAL
        if verdict not in ("REAL", "FP"):
            verdict     = "REAL"
            explanation = f"Unexpected verdict '{verdict}' — defaulting to REAL."

        finding["ai_verdict"]     = verdict
        finding["ai_explanation"] = explanation

    except (KeyError, IndexError, json.JSONDecodeError) as e:
        finding["ai_verdict"]     = "REAL"
        finding["ai_explanation"] = f"Parse error — defaulting to REAL. ({e})"

    return finding
