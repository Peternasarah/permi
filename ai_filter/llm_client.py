# ai_filter/llm_client.py
# The only module in Permi that makes network requests.
#
# 
#
# Priority:
#   Personal API key → direct OpenRouter
#   Community token  → proxy backend
#   Neither          → AI_UNAVAILABLE (offline)

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

# In-memory cache — same finding never hits the API twice per session
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
    rule_id     = finding.get("rule_id", "N/A")
    csp         = finding.get("csp", "not present")
    csp_blocks  = finding.get("csp_blocks_inline", False)
    parameter   = finding.get("parameter", "")
    evidence    = finding.get("evidence", "N/A")

    base = f"""You are a senior application security engineer reviewing automated web scanner results.

Analyze this potential vulnerability and decide if it is a true positive or false positive.

--- FINDING ---
Rule ID    : {rule_id} — {finding.get('rule_name', 'N/A')}
Severity   : {finding.get('severity', 'N/A')}
File/URL   : {finding.get('file', 'N/A')}
Line       : {finding.get('line_number', 'N/A')}
Code       : {finding.get('line_content', 'N/A')}
Evidence   : {evidence}
Description: {finding.get('description', 'N/A')}"""

    # XSS-specific guidance with context-aware reflection analysis
    if rule_id == "WEB_XSS001":
        base += f"""
Parameter  : {parameter}
Payload    : {finding.get('payload', 'N/A')}
CSP Header : {csp[:200] if csp and csp != 'not present' else 'not present'}
CSP blocks inline scripts: {'YES' if csp_blocks else 'NO'}
---------------

CRITICAL GUIDANCE FOR XSS VERDICT:

1. REFLECTION CONTEXT IS EVERYTHING — this is the most important factor:
   - If the payload appears ONLY inside an HTML attribute (href=, value=,
     data-*, action=, src=, class=), inside a JSON string within an attribute,
     or as part of a URL query string inside an attribute → mark as FP.
     These contexts CANNOT execute JavaScript even if unencoded.
   - Only mark REAL if the payload appears inside a <script> block, an inline
     event handler (onclick=, onerror=, onload=), or as raw untagged HTML
     content between elements where it would be parsed as executable markup.

2. PARAMETER NAME SIGNALS:
   - utm_source, utm_campaign, utm_medium, utm_content, utm_term → almost
     always FP. These are analytics-only parameters never rendered as HTML.
   - ref_cta, ref_loc, ref_page → marketing tracking, almost always FP.
   - locale, lang → usually reflected in safe attribute contexts, almost FP.
   - topic, q, search, with, scid → higher risk, examine context carefully.

3. CSP RULES:
   - If CSP blocks inline scripts (YES above) → even real reflection cannot
     execute. Mark as FP unless a CSP bypass is evident.
   - If no CSP and payload in executable context → mark REAL.

4. WELL-ENGINEERED SITES (GitHub, Google, Microsoft, Cloudflare):
   - These sites have mature security teams and extensive XSS protections.
   - Reflection in attribute contexts on these sites is almost certainly FP.
   - Only mark REAL if you see strong evidence of executable context."""

    base += """
---------------

Respond with a JSON object ONLY. No explanation outside the JSON. No markdown fences.

{"is_true_positive": true or false, "confidence": integer 0-100, "reason": "one sentence max 20 words"}"""

    return base


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


# ── Backend A — Direct OpenRouter ─────────────────────────────────────────────
def _analyse_direct(finding: dict, api_key: str) -> dict:
    """Send finding directly to OpenRouter using personal API key."""
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

            raw_content              = response.json()["choices"][0]["message"]["content"]
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


# ── Backend B — Community Proxy ────────────────────────────────────────────────
def _analyse_proxy(finding: dict, token: str) -> dict:
    """Send finding to community proxy using anonymous token."""
    proxy_url = get_proxy_url()

    payload = {
        "rule_id":      finding.get("rule_id", ""),
        "rule_name":    finding.get("rule_name", ""),
        "severity":     finding.get("severity", "low"),
        "file":         finding.get("file", ""),
        "line_number":  finding.get("line_number", 0),
        "line_content": finding.get("line_content", ""),
        "description":  finding.get("description", ""),
    }

    try:
        response = requests.post(
            f"{proxy_url}/v1/analyze",
            headers={
                "Content-Type":   "application/json",
                "X-Permi-Token":  token,
            },
            json=payload,
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

        verdict    = data.get("verdict", "AI_UNAVAILABLE")
        confidence = data.get("confidence")
        reason     = data.get("reason", "No reason provided.")
        remaining  = data.get("credits_remaining")
        message    = data.get("message")

        # Store remaining credits so filter.py can display them
        finding["ai_verdict"]            = verdict
        finding["ai_confidence"]         = confidence
        finding["ai_explanation"]        = reason
        finding["ai_backend"]            = "community"
        finding["community_credits_left"] = remaining
        finding["community_message"]     = message
        return finding

    except Exception:
        finding["ai_verdict"]     = "AI_UNAVAILABLE"
        finding["ai_confidence"]  = None
        finding["ai_explanation"] = "Community proxy unavailable — review manually."
        finding["ai_backend"]     = "community"
        return finding


# ── Public API ────────────────────────────────────────────────────────────────
def analyse(finding: dict) -> dict:
    """
    Route finding to the correct backend:
      Personal API key → direct OpenRouter
      Community token  → community proxy
      Neither          → AI_UNAVAILABLE
    """
    # Cache check
    key = _cache_key(finding)
    if key in _cache:
        cached = _cache[key]
        finding["ai_verdict"]     = cached["verdict"]
        finding["ai_confidence"]  = cached["confidence"]
        finding["ai_explanation"] = cached["reason"] + " [cached]"
        finding["ai_backend"]     = cached.get("backend", "cache")
        return finding

    token   = get_community_token()
    api_key = get_api_key() if not token else None

    # Priority: community token > personal API key.
    # If the user ran `permi setup --community`, use the proxy.
    # Only fall back to API key if no community token is configured.
    # This prevents the .env file from silently overriding a community setup.

    if token:
        result = _analyse_proxy(finding, token)
    elif api_key:
        result = _analyse_direct(finding, api_key)
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

    # Cache successful verdicts (not AI_UNAVAILABLE)
    if result.get("ai_verdict") != "AI_UNAVAILABLE":
        _cache[key] = {
            "verdict":    result["ai_verdict"],
            "confidence": result["ai_confidence"],
            "reason":     result["ai_explanation"],
            "backend":    result.get("ai_backend", ""),
        }

    return result
