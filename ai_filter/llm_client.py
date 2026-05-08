# ai_filter/llm_client.py  — v0.3 (Fix A: CSP-aware prompt)
#
# FIX A — CSP-AWARE PROMPT:
#   _build_prompt() now includes the target's Content-Security-Policy
#   value and whether it blocks inline scripts. This gives the AI the
#   context it needs to correctly verdict XSS findings on hardened targets
#   like github.com — where reflection exists but CSP blocks execution.
#
# All other logic (routing, caching, retries) is unchanged.

from __future__ import annotations

import os
import json
import time
import hashlib
import requests
from db.config import get_api_key, get_community_token, get_proxy_url

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL          = os.environ.get("PERMI_LLM_MODEL", "deepseek/deepseek-chat")
TIMEOUT        = 30
MAX_RETRIES    = 3

HIGH_THRESHOLD = 75
LOW_THRESHOLD  = 35

_cache: dict[str, dict] = {}


def _cache_key(finding: dict) -> str:
    raw = (
        str(finding.get("rule_id", ""))
        + str(finding.get("file", ""))
        + str(finding.get("line_number", ""))
        + str(finding.get("line_content", ""))
    )
    return hashlib.md5(raw.encode("utf-8")).hexdigest()


def _build_prompt(finding: dict) -> str:
    """
    FIX A: Build a CSP-aware prompt for XSS findings.
    For WEB_XSS001 findings, the prompt now includes:
      - The Content-Security-Policy header value (if present)
      - Whether the CSP blocks inline script execution
    This prevents the AI from calling reflected XSS "REAL" on targets
    that have a strong CSP (like github.com) where alert() cannot execute.
    """
    rule_id = finding.get("rule_id", "")

    # ── Standard fields (all findings) ────────────────────────────────────────
    base_context = f"""You are a senior application security engineer reviewing automated web scanner results.

Analyze this potential vulnerability and decide if it is a true positive or false positive.

--- FINDING ---
Rule ID    : {rule_id} — {finding.get('rule_name', 'N/A')}
Severity   : {finding.get('severity', 'N/A')}
File/URL   : {finding.get('file', 'N/A')}
Line       : {finding.get('line_number', 'N/A')}
Code       : {finding.get('line_content', 'N/A')}
Evidence   : {finding.get('evidence', 'N/A')}
Description: {finding.get('description', 'N/A')}"""

    # ── FIX A: XSS-specific CSP context ───────────────────────────────────────
    if rule_id == "WEB_XSS001":
        csp            = finding.get("csp", "not present")
        csp_blocks     = finding.get("csp_blocks_inline", False)
        parameter      = finding.get("parameter", "N/A")
        payload        = finding.get("payload", "N/A")

        csp_section = f"""
Parameter  : {parameter}
Payload    : {payload}
CSP Header : {csp[:200] if csp and csp != 'not present' else 'not present'}
CSP blocks inline scripts: {'YES — alert() cannot execute in browser' if csp_blocks else 'NO — inline scripts are allowed'}
---------------

IMPORTANT GUIDANCE FOR XSS ANALYSIS:
- Reflection in the raw HTTP response body does NOT prove exploitability.
- If "CSP blocks inline scripts: YES", the payload CANNOT execute in a browser
  even if reflected. Verdict should be FP unless the CSP has bypass vectors.
- If "CSP blocks inline scripts: NO" and the payload is reflected unencoded
  in an HTML context (not inside a URL or comment), this is likely REAL.
- UTM tracking parameters (utm_source, utm_campaign, utm_medium, utm_content),
  locale parameters, and marketing parameters (ref_cta, ref_loc, ref_page)
  are typically used for analytics only and are NOT reflected into executable
  HTML contexts on well-engineered sites. High suspicion of FP for these.
- Parameters like 'with', 'topic', 'scid', 'source' on non-marketing pages
  deserve higher scrutiny and may be genuinely reflected."""

        prompt_body = base_context + csp_section

    else:
        # Non-XSS findings — use original prompt format
        prompt_body = base_context + "\n---------------"

    prompt_body += """

Respond with a JSON object ONLY. No explanation outside the JSON. No markdown fences.

{"is_true_positive": true or false, "confidence": integer 0-100, "reason": "one sentence max 20 words"}"""

    return prompt_body


def _parse_response(raw: str) -> tuple[str, int, str]:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        lines   = cleaned.splitlines()
        cleaned = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    data       = json.loads(cleaned)
    is_tp      = bool(data.get("is_true_positive", True))
    confidence = max(0, min(100, int(data.get("confidence", 50))))
    reason     = str(data.get("reason", "No reason provided."))

    if not is_tp or confidence <= LOW_THRESHOLD:
        verdict = "FP"
    elif confidence >= HIGH_THRESHOLD:
        verdict = "REAL"
    else:
        verdict = "REVIEW"

    return verdict, confidence, reason


def _is_ssl_eof_error(error: Exception) -> bool:
    msg = str(error)
    return (
        "UNEXPECTED_EOF_WHILE_READING" in msg
        or "EOF occurred in violation of protocol" in msg
        or "SSLEOFError" in msg
        or "Connection reset by peer" in msg
        or "RemoteDisconnected" in msg
    )


def _analyse_direct(finding: dict, api_key: str) -> dict:
    prompt     = _build_prompt(finding)
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
                    "max_tokens":  120,
                },
                timeout=TIMEOUT,
            )
            response.raise_for_status()

            raw_content                 = response.json()["choices"][0]["message"]["content"]
            verdict, confidence, reason = _parse_response(raw_content)

            finding["ai_verdict"]     = verdict
            finding["ai_confidence"]  = confidence
            finding["ai_explanation"] = reason
            finding["ai_backend"]     = "direct"
            return finding

        except requests.exceptions.Timeout:
            last_error = "request timed out"
            if attempt < MAX_RETRIES - 1:
                time.sleep((2 ** attempt) * 1.5)
            continue

        except requests.exceptions.RequestException as exc:
            if _is_ssl_eof_error(exc):
                last_error = "SSL connection error"
                if attempt < MAX_RETRIES - 1:
                    time.sleep((2 ** attempt) * 1.5)
                continue
            else:
                last_error = "network error"
                break

        except (ValueError, KeyError, IndexError, json.JSONDecodeError) as exc:
            last_error = f"response parse error ({exc})"
            break

    finding["ai_verdict"]     = "AI_UNAVAILABLE"
    finding["ai_confidence"]  = None
    finding["ai_explanation"] = f"AI filter unavailable ({last_error}) — review manually."
    finding["ai_backend"]     = "direct"
    return finding


def _analyse_proxy(finding: dict, token: str) -> dict:
    proxy_url = get_proxy_url()

    payload = {
        "rule_id":           finding.get("rule_id", ""),
        "rule_name":         finding.get("rule_name", ""),
        "severity":          finding.get("severity", "low"),
        "file":              finding.get("file", ""),
        "line_number":       finding.get("line_number", 0),
        "line_content":      finding.get("line_content", ""),
        "description":       finding.get("description", ""),
        "evidence":          finding.get("evidence", ""),
        # FIX A: include CSP fields so proxy backend can use them too
        "csp":               finding.get("csp", "not present"),
        "csp_blocks_inline": finding.get("csp_blocks_inline", False),
        "parameter":         finding.get("parameter", ""),
        "payload":           finding.get("payload", ""),
    }

    try:
        response = requests.post(
            f"{proxy_url}/v1/analyze",
            headers={
                "Content-Type":  "application/json",
                "X-Permi-Token": token,
            },
            json=payload,
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

        finding["ai_verdict"]             = data.get("verdict", "AI_UNAVAILABLE")
        finding["ai_confidence"]          = data.get("confidence")
        finding["ai_explanation"]         = data.get("reason", "No reason provided.")
        finding["ai_backend"]             = "community"
        finding["community_credits_left"] = data.get("credits_remaining")
        finding["community_message"]      = data.get("message")
        return finding

    except Exception:
        finding["ai_verdict"]     = "AI_UNAVAILABLE"
        finding["ai_confidence"]  = None
        finding["ai_explanation"] = "Community proxy unavailable — review manually."
        finding["ai_backend"]     = "community"
        return finding


def analyse(finding: dict) -> dict:
    """
    Route finding to correct backend:
      Personal API key → direct OpenRouter (CSP-aware prompt)
      Community token  → community proxy (CSP fields included)
      Neither          → AI_UNAVAILABLE
    """
    key = _cache_key(finding)
    if key in _cache:
        cached = _cache[key]
        finding["ai_verdict"]     = cached["verdict"]
        finding["ai_confidence"]  = cached["confidence"]
        finding["ai_explanation"] = cached["reason"] + " [cached]"
        finding["ai_backend"]     = cached.get("backend", "cache")
        return finding

    api_key = get_api_key()
    token   = get_community_token()

    if api_key:
        result = _analyse_direct(finding, api_key)
    elif token:
        result = _analyse_proxy(finding, token)
    else:
        finding["ai_verdict"]     = "AI_UNAVAILABLE"
        finding["ai_confidence"]  = None
        finding["ai_explanation"] = (
            "No API key or community token configured. "
            "Run: permi setup --api-key YOUR_KEY  "
            "or:  permi setup --community"
        )
        finding["ai_backend"] = "none"
        return finding

    if result.get("ai_verdict") != "AI_UNAVAILABLE":
        _cache[key] = {
            "verdict":    result["ai_verdict"],
            "confidence": result["ai_confidence"],
            "reason":     result["ai_explanation"],
            "backend":    result.get("ai_backend", ""),
        }

    return result
