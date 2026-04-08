# ai_filter/llm_client.py
# The only module in Permi that makes network requests.
# Sends a finding to OpenRouter and returns a verdict:
#   REAL  — this is a genuine vulnerability
#   FP    — this is a false positive, ignore it
#
# API key is loaded via config.py priority chain.
# If no key found anywhere, defaults to REAL (safe fallback).

import json
import requests
from db.config import get_api_key

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL          = "deepseek/deepseek-chat"
TIMEOUT        = 30


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


def analyse(finding: dict) -> dict:
    """
    Send one finding to the LLM and return the finding dict
    updated with ai_verdict and ai_explanation.

    If the API call fails for any reason, we default to REAL
    so nothing gets silently dropped.
    """
    api_key = get_api_key()

    if not api_key:
        finding["ai_verdict"]     = "REAL"
        finding["ai_explanation"] = "No API key found — AI filter skipped."
        return finding

    prompt = _build_prompt(finding)

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

    except requests.exceptions.Timeout:
        finding["ai_verdict"]     = "REAL"
        finding["ai_explanation"] = "API timeout — defaulting to REAL."
        return finding

    except requests.exceptions.RequestException as e:
        finding["ai_verdict"]     = "REAL"
        finding["ai_explanation"] = f"API error — defaulting to REAL. ({e})"
        return finding

    try:
        content     = response.json()["choices"][0]["message"]["content"].strip()
        lines       = content.splitlines()
        verdict     = lines[0].strip().upper()
        explanation = lines[1].strip() if len(lines) > 1 else "No explanation provided."

        if verdict not in ("REAL", "FP"):
            verdict     = "REAL"
            explanation = f"Unexpected verdict '{verdict}' — defaulting to REAL."

        finding["ai_verdict"]     = verdict
        finding["ai_explanation"] = explanation

    except (KeyError, IndexError, json.JSONDecodeError) as e:
        finding["ai_verdict"]     = "REAL"
        finding["ai_explanation"] = f"Parse error — defaulting to REAL. ({e})"

    return finding
