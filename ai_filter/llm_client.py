# ai_filter/llm_client.py
# The only module in Permi that makes network requests.
#

from __future__ import annotations

import os
import json
import time
import hashlib
import requests
from db.config import get_api_key

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL          = os.environ.get("PERMI_LLM_MODEL", "deepseek/deepseek-chat")
TIMEOUT        = 30
MAX_RETRIES    = 3

# ── Confidence thresholds ─────────────────────────────────────────────────────
# confidence >= HIGH_THRESHOLD  → REAL   (show to user, fix this)
# confidence <= LOW_THRESHOLD   → FP     (drop silently)
# between                       → REVIEW (show with manual review label)
HIGH_THRESHOLD = 75
LOW_THRESHOLD  = 35

# ── In-memory cache ───────────────────────────────────────────────────────────
# Keyed by a hash of rule_id + file + line_number + line_content.
# Cleared when the process exits — never persists between scans.
# This means identical findings in the same scan session never hit the API twice.
_cache: dict[str, dict] = {}


def _cache_key(finding: dict) -> str:
    """Generate a stable cache key for a finding."""
    raw = (
        str(finding.get("rule_id", ""))
        + str(finding.get("file", ""))
        + str(finding.get("line_number", ""))
        + str(finding.get("line_content", ""))
    )
    return hashlib.md5(raw.encode("utf-8")).hexdigest()


def _build_prompt(finding: dict) -> str:
    """
    Build a structured JSON prompt.
    Asking for JSON output makes parsing reliable — no fragile text splitting.
    """
    return f"""You are a senior application security engineer reviewing automated SAST scan results.

Analyze this potential vulnerability and decide if it is a true positive or false positive.

--- FINDING ---
Rule ID    : {finding.get('rule_id', 'N/A')}
Rule Name  : {finding.get('rule_name', 'N/A')}
Severity   : {finding.get('severity', 'N/A')}
File       : {finding.get('file', 'N/A')}
Line       : {finding.get('line_number', 'N/A')}
Code       : {finding.get('line_content', 'N/A')}
Description: {finding.get('description', 'N/A')}
---------------

Consider:
- Is this code actually reachable and exploitable?
- Is the flagged pattern in executable code or in a comment, string, or template?
- Does the context suggest user-controlled input reaches the vulnerable point?

Respond with a JSON object ONLY. No explanation outside the JSON. No markdown fences.

{{
  "is_true_positive": true or false,
  "confidence": integer between 0 and 100,
  "reason": "one sentence, max 20 words"
}}"""


def _parse_response(raw: str) -> tuple[str, int, str]:
    """
    Parse the LLM JSON response into (verdict, confidence, reason).

    Verdict mapping:
      confidence >= HIGH_THRESHOLD AND is_true_positive → REAL
      confidence <= LOW_THRESHOLD  OR NOT is_true_positive → FP
      everything else → REVIEW

    Returns (verdict, confidence, reason) or raises ValueError on bad JSON.
    """
    # Strip markdown fences if the model added them despite instructions
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        lines   = cleaned.splitlines()
        cleaned = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    data       = json.loads(cleaned)
    is_tp      = bool(data.get("is_true_positive", True))
    confidence = int(data.get("confidence", 50))
    reason     = str(data.get("reason", "No reason provided."))

    # Clamp confidence to 0-100
    confidence = max(0, min(100, confidence))

    # Determine verdict based on confidence thresholds
    if not is_tp or confidence <= LOW_THRESHOLD:
        verdict = "FP"
    elif confidence >= HIGH_THRESHOLD:
        verdict = "REAL"
    else:
        verdict = "REVIEW"

    return verdict, confidence, reason


def _is_ssl_eof_error(error: Exception) -> bool:
    """Return True if this is the common OpenRouter SSL EOF issue."""
    msg = str(error)
    return (
        "UNEXPECTED_EOF_WHILE_READING" in msg
        or "EOF occurred in violation of protocol" in msg
        or "SSLEOFError" in msg
        or "Connection reset by peer" in msg
        or "RemoteDisconnected" in msg
    )


def analyse(finding: dict) -> dict:
    """
    Send one finding to the LLM and return the finding dict updated with:
      ai_verdict      — REAL / REVIEW / FP / AI_UNAVAILABLE
      ai_confidence   — 0-100 (None if API unavailable)
      ai_explanation  — one-sentence reason

    Cache:
      If an identical finding was already analysed this session,
      the cached result is returned immediately without an API call.

    Retry:
      SSL/network errors → retry up to MAX_RETRIES times with backoff.
      Other errors       → fail immediately.
      All retries fail   → AI_UNAVAILABLE (never silently becomes REAL).
    """
    api_key = get_api_key()

    if not api_key:
        finding["ai_verdict"]     = "REAL"
        finding["ai_confidence"]  = None
        finding["ai_explanation"] = "No API key — AI filter skipped."
        return finding

    # ── Cache check ───────────────────────────────────────────────────────────
    key = _cache_key(finding)
    if key in _cache:
        cached = _cache[key]
        finding["ai_verdict"]     = cached["verdict"]
        finding["ai_confidence"]  = cached["confidence"]
        finding["ai_explanation"] = cached["reason"] + " [cached]"
        return finding

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
                    "max_tokens":  120,  # slightly more room for JSON
                },
                timeout=TIMEOUT,
            )
            response.raise_for_status()

            raw_content = response.json()["choices"][0]["message"]["content"]
            verdict, confidence, reason = _parse_response(raw_content)

            # Store in cache
            _cache[key] = {
                "verdict":    verdict,
                "confidence": confidence,
                "reason":     reason,
            }

            finding["ai_verdict"]     = verdict
            finding["ai_confidence"]  = confidence
            finding["ai_explanation"] = reason
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

    # ── All retries exhausted ─────────────────────────────────────────────────
    finding["ai_verdict"]     = "AI_UNAVAILABLE"
    finding["ai_confidence"]  = None
    finding["ai_explanation"] = f"AI filter unavailable ({last_error}) — review manually."
    return finding
