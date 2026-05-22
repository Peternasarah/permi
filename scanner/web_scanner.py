# scanner/web_scanner.py
# Web vulnerability scanner — HTTP-based and JS-based active scanning engine.
# Handles: SQL injection (error, boolean, time, union), XSS, security headers, info gathering, crawling.
# Used by: permi scan --url https://target.com
#


from __future__ import annotations

import asyncio
import socket
import time
import hashlib
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urlparse, urljoin, parse_qs
from collections import deque
from datetime import datetime

import httpx
from bs4 import BeautifulSoup


# ── USER AGENT ────────────────────────────────────────────────────────────────
USER_AGENT = (
    "Permi Security Scanner/0.5 "
    "(github.com/Peternasarah/permi; authorized security testing only)"
)

# ── SQL ERROR SIGNATURES ──────────────────────────────────────────────────────
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql command not properly ended",
    "postgresql query failed",
    "ora-01756",
    "sqlite3::",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "pg_query",
    "supplied argument is not a valid mysql",
]

# ── PAYLOAD LIBRARY ───────────────────────────────────────────────────────────
SQL_PAYLOADS = {
    "error_based":   ["'", '"', "\\", ";", "'--", "'/*"],
    "boolean_based": [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR 1=1--",
        "') OR ('1'='1",
    ],
    "time_based": [
        "'; SELECT SLEEP(5)--",
        "1' AND SLEEP(5)--",
    ],
    "union_based": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
    ],
}

XSS_PAYLOADS = [
    "<script>alert('PERMI_XSS')</script>",
    "<img src=x onerror=alert('PERMI_XSS')>",
    "<svg onload=alert('PERMI_XSS')>",
    "<body onload=alert('PERMI_XSS')>",
    "\"><script>alert('PERMI_XSS')</script>",
    "'><script>alert('PERMI_XSS')</script>",
    "<ScRiPt>alert('PERMI_XSS')</sCrIpT>",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# ── KNOWN SMALL RESPONSE SIZES (redirect/error pages) ────────────────────────
# Responses this size are login redirects, error pages, or 302s.
# They will always produce size differences with SQL payloads — false positives.
KNOWN_FP_SIZES = {9593, 285, 118, 1523}
MIN_BOOLEAN_RESPONSE_BYTES = 2000   # responses smaller than this are redirects

# ── TRACKING / MARKETING PARAMETERS ──────────────────────────────────────────
# These parameters are used by every website for analytics and URL routing.
# They reflect harmlessly and generate enormous noise on any well-secured site.
# Never genuine XSS or SQLi vectors — always false positives on hardened targets.
LIKELY_NON_REFLECTIVE_PARAMS = {
    # Marketing tracking (UTM)
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    # Internal referral tracking
    "ref_cta", "ref_loc", "ref_page", "ref_source", "ref",
    # Locale / language
    "locale", "lang", "language", "hl",
    # Microsoft / Bing ads
    "ocid", "scid", "cft",
    # Facebook / Google / Microsoft click IDs
    "fbclid", "gclid", "msclkid", "dclid", "wbraid", "gbraid",
    # Mailchimp
    "mc_cid", "mc_eid",
    # Auth / CSRF — sensitive but not injection vectors
    "next", "redirect", "redirect_to", "return", "callback",
    "state", "nonce", "csrf", "token", "_token",
}

# ── SPA FRAMEWORK SIGNATURES ──────────────────────────────────────────────────
JS_FRAMEWORK_SIGNATURES = [
    "react", "vue", "angular", "svelte", "next", "nuxt", "remix",
    "ng-version", "__next", "__nuxt", "data-reactroot",
    "app.bundle.js", "main.chunk.js", "runtime.js",
]


# ── DOMAIN HELPERS ────────────────────────────────────────────────────────────

def _extract_base_domain(netloc: str) -> str:
    host  = netloc.split(":")[0].lower()
    parts = host.split(".")
    two_part_tlds = {
        "edu.ng", "co.uk", "com.ng", "org.ng", "gov.ng",
        "net.ng", "com.au", "co.za", "ac.uk", "org.uk",
        "co.nz", "com.br", "co.in",
    }
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_part_tlds:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _is_same_scope(url: str, base_domain: str, include_subdomains: bool) -> bool:
    netloc = urlparse(url).netloc.split(":")[0].lower()
    if not netloc:
        return False
    if include_subdomains:
        return _extract_base_domain(netloc) == base_domain
    return netloc == base_domain


def _detect_spa(html: str) -> bool:
    """Heuristic: is this a JavaScript-rendered single-page application?"""
    lower = html.lower()
    # Signature-based: count framework markers
    sig_count = sum(1 for s in JS_FRAMEWORK_SIGNATURES if s in lower)
    if sig_count >= 2:
        return True
    # Heuristic: large page with very few links
    soup = BeautifulSoup(html, "html.parser")
    return len(html) > 5000 and len(soup.find_all("a", href=True)) < 3


def _dedup_urls(urls) -> List[str]:
    """
    Deduplicate parameterised URLs by (netloc + path + frozenset of param names).
    Same endpoint with same param names but different values = same test target.
    """
    seen = set()
    out  = []
    for url in urls:
        if "?" not in url:
            continue
        p   = urlparse(url)
        key = (p.netloc, p.path, frozenset(parse_qs(p.query).keys()))
        if key not in seen:
            seen.add(key)
            out.append(url)
    return out


# ── SQL INJECTION SCANNER ─────────────────────────────────────────────────────
class SQLInjectionScanner:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def test_url(self, url: str) -> List[Dict]:
        findings = []
        parsed   = urlparse(url)
        params   = parse_qs(parsed.query)

        if not params:
            return findings

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param, values in params.items():
            # Skip all tracking/marketing/auth parameters — always false positives
            if param.lower() in LIKELY_NON_REFLECTIVE_PARAMS:
                continue

            original = values[0] if values else ""
            findings.extend(await self._test_error_based(base_url, param, original, params))
            findings.extend(await self._test_boolean_based(base_url, param, original, params))
            findings.extend(await self._test_time_based(base_url, param, original, params))
            findings.extend(await self._test_union_based(base_url, param, original, params))

        return findings

    async def _test_error_based(self, base_url, param, value, params):
        findings = []
        for payload in SQL_PAYLOADS["error_based"]:
            test_params        = {k: v for k, v in params.items()}
            test_params[param] = [value + payload]
            try:
                response = await self.client.get(base_url, params=test_params, timeout=10)
                lower    = response.text.lower()
                for error in SQL_ERRORS:
                    if error in lower:
                        findings.append({
                            "rule_id":        "WEB_SQL001",
                            "rule_name":      "SQL Injection — Error-based",
                            "severity":       "high",
                            "description":    (
                                f"A SQL error was returned when a quote character was injected "
                                f"into parameter '{param}'. This is strong evidence of unsanitised "
                                f"SQL query construction."
                            ),
                            "file":           base_url,
                            "line_number":    0,
                            "line_content":   f"?{param}={value}{payload}",
                            "parameter":      param,
                            "payload":        payload,
                            "evidence":       f"DB error: {error}",
                            "ai_verdict":     None,
                            "ai_explanation": None,
                        })
                        return findings
            except Exception:
                continue
        return findings

    async def _test_boolean_based(self, base_url, param, value, params):
        findings = []
        try:
            baseline     = await self.client.get(base_url, params=params, timeout=10)
            baseline_len = len(baseline.text)

            # If baseline is a known small redirect/error page, skip entirely
            if baseline_len in KNOWN_FP_SIZES or baseline_len < MIN_BOOLEAN_RESPONSE_BYTES:
                return findings

            for payload in SQL_PAYLOADS["boolean_based"][:3]:
                test_params        = {k: v for k, v in params.items()}
                test_params[param] = [value + payload]
                false_payload      = (
                    payload
                    .replace("'1'='1'", "'1'='2'")
                    .replace("1=1", "1=2")
                )
                false_params        = {k: v for k, v in params.items()}
                false_params[param] = [value + false_payload]
                try:
                    resp_true  = await self.client.get(base_url, params=test_params,  timeout=10)
                    resp_false = await self.client.get(base_url, params=false_params, timeout=10)
                    true_len   = len(resp_true.text)
                    false_len  = len(resp_false.text)

                    # Reject if either response is a known small redirect/error page
                    if (
                        true_len  in KNOWN_FP_SIZES
                        or false_len in KNOWN_FP_SIZES
                        or true_len  < MIN_BOOLEAN_RESPONSE_BYTES
                        or false_len < MIN_BOOLEAN_RESPONSE_BYTES
                    ):
                        continue

                    # Require a substantial difference — not a minor size variation
                    if abs(true_len - false_len) > 500 and abs(true_len - baseline_len) > 200:
                        findings.append({
                            "rule_id":        "WEB_SQL002",
                            "rule_name":      "SQL Injection — Boolean-based Blind",
                            "severity":       "high",
                            "description":    (
                                f"Parameter '{param}' returns significantly different response "
                                f"sizes for true vs false SQL conditions. "
                                f"Both responses are substantial pages (not redirect pages), "
                                f"suggesting the input may be embedded in a database query."
                            ),
                            "file":           base_url,
                            "line_number":    0,
                            "line_content":   f"?{param}={value}{payload}",
                            "parameter":      param,
                            "payload":        payload,
                            "evidence":       f"TRUE: {true_len}b, FALSE: {false_len}b, baseline: {baseline_len}b",
                            "ai_verdict":     None,
                            "ai_explanation": None,
                        })
                        return findings
                except Exception:
                    continue
        except Exception:
            pass
        return findings

    async def _test_time_based(self, base_url, param, value, params):
        findings = []
        try:
            start         = time.time()
            await self.client.get(base_url, params=params, timeout=12)
            baseline_time = time.time() - start

            for payload in SQL_PAYLOADS["time_based"]:
                test_params        = {k: v for k, v in params.items()}
                test_params[param] = [value + payload]
                try:
                    start   = time.time()
                    await self.client.get(base_url, params=test_params, timeout=20)
                    elapsed = time.time() - start

                    # Require minimum 8 seconds AND at least 4 seconds over baseline.
                    # This prevents network hiccups, rate-limit throttles, and CDN
                    # slow responses from being misidentified as time-based SQLi.
                    if elapsed >= 8 and elapsed > baseline_time + 4:
                        findings.append({
                            "rule_id":        "WEB_SQL003",
                            "rule_name":      "SQL Injection — Time-based Blind",
                            "severity":       "high",
                            "description":    (
                                f"A time-delay SQL payload caused a {elapsed:.1f}s response "
                                f"(baseline: {baseline_time:.1f}s) on parameter '{param}'. "
                                f"Verify manually — severe network latency can occasionally "
                                f"produce false positives on this check."
                            ),
                            "file":           base_url,
                            "line_number":    0,
                            "line_content":   f"?{param}={value}{payload}",
                            "parameter":      param,
                            "payload":        payload,
                            "evidence":       f"Response: {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                            "ai_verdict":     None,
                            "ai_explanation": None,
                        })
                        return findings
                except asyncio.TimeoutError:
                    # Hard timeout (>20s) is stronger evidence than slow response
                    findings.append({
                        "rule_id":        "WEB_SQL003",
                        "rule_name":      "SQL Injection — Time-based Blind",
                        "severity":       "high",
                        "description":    (
                            f"Parameter '{param}' caused a request timeout (>20s) "
                            f"with a time-delay SQL payload. "
                            f"Baseline was {baseline_time:.1f}s. Verify manually."
                        ),
                        "file":           base_url,
                        "line_number":    0,
                        "line_content":   f"?{param}={value}{payload}",
                        "parameter":      param,
                        "payload":        payload,
                        "evidence":       f"Request timed out (>20s, baseline: {baseline_time:.1f}s)",
                        "ai_verdict":     None,
                        "ai_explanation": None,
                    })
                    return findings
                except Exception:
                    continue
        except Exception:
            pass
        return findings

    async def _test_union_based(self, base_url, param, value, params):
        """Test for UNION-based SQL injection by checking for extra columns in response."""
        findings = []
        try:
            baseline = await self.client.get(base_url, params=params, timeout=10)
            baseline_text = baseline.text

            for payload in SQL_PAYLOADS["union_based"]:
                test_params        = {k: v for k, v in params.items()}
                test_params[param] = [value + payload]
                try:
                    response = await self.client.get(base_url, params=test_params, timeout=10)
                    response_text = response.text

                    # Union-based SQLi often changes the response structure significantly
                    # or introduces NULL values that change the page rendering
                    # We look for significant size changes or structural differences
                    baseline_len = len(baseline_text)
                    response_len = len(response_text)

                    # Skip if either is a known false-positive size
                    if baseline_len in KNOWN_FP_SIZES or response_len in KNOWN_FP_SIZES:
                        continue
                    if baseline_len < MIN_BOOLEAN_RESPONSE_BYTES or response_len < MIN_BOOLEAN_RESPONSE_BYTES:
                        continue

                    # Look for significant structural change
                    if abs(response_len - baseline_len) > 500:
                        # Additional check: look for common UNION indicators
                        union_indicators = [
                            "null", "NULL", "unknown column", "operand should contain",
                            "the used select statements have a different number of columns",
                        ]
                        has_union_error = any(ind in response_text.lower() for ind in union_indicators)

                        if has_union_error or response_len > baseline_len + 500:
                            findings.append({
                                "rule_id":        "WEB_SQL004",
                                "rule_name":      "SQL Injection — Union-based",
                                "severity":       "high",
                                "description":    (
                                    f"Parameter '{param}' produced a significantly different "
                                    f"response when a UNION SELECT payload was injected. "
                                    f"This suggests the application may be vulnerable to "
                                    f"UNION-based SQL injection, allowing data extraction."
                                ),
                                "file":           base_url,
                                "line_number":    0,
                                "line_content":   f"?{param}={value}{payload}",
                                "parameter":      param,
                                "payload":        payload,
                                "evidence":       (
                                    f"Baseline: {baseline_len}b, UNION: {response_len}b. "
                                    f"Union error indicator: {has_union_error}"
                                ),
                                "ai_verdict":     None,
                                "ai_explanation": None,
                            })
                            return findings
                except Exception:
                    continue
        except Exception:
            pass
        return findings


# ── XSS SCANNER ───────────────────────────────────────────────────────────────
class XSSScanner:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def test_url(self, url: str, csp: str | None = None) -> List[Dict]:
        findings = []
        parsed   = urlparse(url)
        params   = parse_qs(parsed.query)

        if not params:
            return findings

        base_url  = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        csp_value = csp or ""
        csp_blocks = self._csp_blocks_inline(csp_value) if csp_value else False

        for param, values in params.items():
            # Skip all tracking/marketing parameters — always false positives
            if param.lower() in LIKELY_NON_REFLECTIVE_PARAMS:
                continue

            marker      = f"permi_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
            test_params = {k: v for k, v in params.items()}
            test_params[param] = [marker]

            try:
                probe = await self.client.get(base_url, params=test_params, timeout=10)
                if marker not in probe.text:
                    # Parameter not reflected at all — skip XSS testing entirely
                    continue

                for payload in XSS_PAYLOADS:
                    test_params[param] = [payload]
                    try:
                        xss_resp = await self.client.get(base_url, params=test_params, timeout=10)
                        if self._is_reflected_unencoded(xss_resp.text, payload):
                            evid = (
                                f"Payload reflected unencoded. CSP: {csp_value[:120]}"
                                if csp_blocks else
                                "Payload reflected unencoded in response"
                            )
                            findings.append({
                                "rule_id":        "WEB_XSS001",
                                "rule_name":      "XSS — Reflected Cross-Site Scripting",
                                "severity":       "high",
                                "description":    (
                                    f"Parameter '{param}' reflects user input into the HTML response "
                                    f"without HTML encoding. An attacker can inject scripts that "
                                    f"execute in a victim's browser."
                                ),
                                "file":           base_url,
                                "line_number":    0,
                                "line_content":   f"?{param}={payload}",
                                "parameter":      param,
                                "payload":        payload,
                                "evidence":       evid,
                                "csp":            csp_value or "not present",
                                "csp_blocks_inline": csp_blocks,
                                "ai_verdict":     None,
                                "ai_explanation": None,
                            })
                            break  # One confirmed finding per parameter is enough
                    except Exception:
                        continue
            except Exception:
                continue

        return findings

    def _is_reflected_unencoded(self, html: str, payload: str) -> bool:
        """
        Return True ONLY if the payload appears UNENCODED in the HTML.

        Checks HTML-encoded versions first — if the site is encoding
        properly, the encoded version will be present instead of the raw
        payload, and we return False (safe site, not XSS).
        """
        # Build the fully HTML-encoded version
        encoded = (
            payload
            .replace("&",  "&amp;")    # must be first
            .replace("<",  "&lt;")
            .replace(">",  "&gt;")
            .replace('"',  "&quot;")
            .replace("'",  "&#x27;")
            .replace("'",  "&#39;")
        )

        # If encoded version is present, the site is escaping correctly
        if encoded.lower() in html.lower():
            return False

        # Also check partial encoding (just the angle brackets)
        if "&lt;" in html and "<script" in payload.lower():
            return False
        if "&lt;" in html and "<img" in payload.lower():
            return False
        if "&lt;" in html and "<svg" in payload.lower():
            return False
        if "&lt;" in html and "<body" in payload.lower():
            return False

        # Only flag if the raw unencoded payload is present
        return payload.lower() in html.lower()

    def _csp_blocks_inline(self, csp: str) -> bool:
        """
        Return True if the CSP header would block inline script execution.
        A CSP blocks inline scripts if it contains script-src or default-src
        WITHOUT 'unsafe-inline'.
        """
        if not csp:
            return False
        csp_lower = csp.lower()
        has_script_src  = "script-src" in csp_lower
        has_default_src = "default-src" in csp_lower
        has_unsafe      = "unsafe-inline" in csp_lower
        has_nonce       = "nonce-" in csp_lower
        has_hash        = "'sha" in csp_lower
        return (has_script_src or has_default_src) and not has_unsafe and not has_nonce and not has_hash


# ── SECURITY HEADERS SCANNER ──────────────────────────────────────────────────
class HeadersScanner:
    async def test_url(self, url: str, client: httpx.AsyncClient) -> Tuple[List[Dict], Optional[str]]:
        findings: List[Dict] = []
        csp_value: Optional[str] = None
        try:
            response = await client.get(url, timeout=10)
            headers  = {k.lower(): v for k, v in response.headers.items()}
            csp_value = headers.get("content-security-policy", None)

            missing = [h for h in SECURITY_HEADERS if h.lower() not in headers]
            if missing:
                findings.append({
                    "rule_id":        "WEB_HDR001",
                    "rule_name":      "Missing Security Headers",
                    "severity":       "medium",
                    "description":    (
                        "The server response is missing one or more recommended security headers. "
                        "These headers protect users from clickjacking, MIME sniffing, and XSS."
                    ),
                    "file":           url,
                    "line_number":    0,
                    "line_content":   f"Missing: {', '.join(missing)}",
                    "evidence":       f"Missing headers: {', '.join(missing)}",
                    "ai_verdict":     None,
                    "ai_explanation": None,
                })

            for header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
                if header.lower() in headers:
                    val = headers[header.lower()]
                    # Only flag if a VERSION NUMBER is disclosed — just "nginx" or
                    # "github.com" is not actionable. "nginx/1.18.0" is.
                    if any(c.isdigit() for c in val) or "/" in val:
                        findings.append({
                            "rule_id":        "WEB_HDR002",
                            "rule_name":      "Server Information Disclosure",
                            "severity":       "low",
                            "description":    (
                                f"The '{header}' header discloses server software version. "
                                f"Attackers use version numbers to target known CVEs."
                            ),
                            "file":           url,
                            "line_number":    0,
                            "line_content":   f"{header}: {val}",
                            "evidence":       f"{header}: {val}",
                            "ai_verdict":     None,
                            "ai_explanation": None,
                        })

        except Exception:
            pass
        return findings, csp_value


# ── INFO GATHERING ────────────────────────────────────────────────────────────
class InfoGatherer:
    async def gather(self, url: str, client: httpx.AsyncClient) -> Dict:
        info   = {"target": url, "timestamp": datetime.now().isoformat()}
        parsed = urlparse(url)
        domain = parsed.netloc

        try:
            ip         = socket.gethostbyname(domain)
            info["ip"] = ip
        except Exception:
            info["ip"] = "Could not resolve"

        try:
            response            = await client.get(url, timeout=10)
            info["status_code"] = response.status_code
            info["server"]      = response.headers.get("Server", "Not disclosed")
            info["powered_by"]  = response.headers.get("X-Powered-By", "Not disclosed")
            info["https"]       = url.startswith("https://")
        except Exception as e:
            info["error"] = str(e)
            info["https"] = url.startswith("https://")

        return info


# ── WEB CRAWLER ───────────────────────────────────────────────────────────────
class WebCrawler:
    def __init__(
        self,
        base_url:           str,
        max_pages:          int  = 30,
        include_subdomains: bool = False,
    ):
        self.base_url           = base_url
        self.max_pages          = max_pages
        self.include_subdomains = include_subdomains
        netloc           = urlparse(base_url).netloc.split(":")[0].lower()
        self.base_domain = _extract_base_domain(netloc)

    async def crawl(self, client: httpx.AsyncClient) -> Tuple[Set[str], bool]:
        visited    = set()
        to_visit   = deque([self.base_url])
        discovered = set([self.base_url])
        is_spa     = False

        scope_msg = (
            f"subdomain-aware ({self.base_domain} + subdomains)"
            if self.include_subdomains
            else f"exact domain only ({self.base_domain})"
        )
        print(f"[Permi] Scope     : {scope_msg}")

        while to_visit and len(visited) < self.max_pages:
            url = to_visit.popleft()
            if url in visited:
                continue
            visited.add(url)

            try:
                response = await asyncio.wait_for(client.get(url, timeout=10), timeout=12.0)
                html     = response.text

                # SPA detection on base URL
                if not is_spa and url == self.base_url:
                    is_spa = _detect_spa(html)

                soup = BeautifulSoup(html, "html.parser")

                for tag in soup.find_all(["a", "form"]):
                    href = tag.get("href") or tag.get("action", "")
                    if not href:
                        continue
                    full = urljoin(url, href)
                    if (
                        _is_same_scope(full, self.base_domain, self.include_subdomains)
                        and full not in visited
                        and full not in discovered
                    ):
                        discovered.add(full)
                        to_visit.append(full)

                await asyncio.sleep(0.2)

            except Exception:
                continue

        return discovered, is_spa


# ── PARALLEL SCAN HELPER ────────────────────────────────────────────────────
async def _scan_single_url(
    target_url: str,
    sql_scanner: SQLInjectionScanner,
    xss_scanner: XSSScanner,
    csp_value: Optional[str],
) -> List[Dict]:
    """Run SQL and XSS scans concurrently for a single URL."""
    results = await asyncio.gather(
        asyncio.wait_for(sql_scanner.test_url(target_url), timeout=45.0),
        asyncio.wait_for(xss_scanner.test_url(target_url, csp=csp_value), timeout=30.0),
        return_exceptions=True,
    )
    findings = []
    for r in results:
        if not isinstance(r, Exception):
            findings.extend(r)
    return findings


# ── MAIN WEB SCAN ORCHESTRATOR ────────────────────────────────────────────────
async def _run_web_scan(
    url:                str,
    max_pages:          int  = 30,
    include_subdomains: bool = False,
    use_js:             bool = False,
    page_timeout_ms:    int  = 20000,
) -> Tuple[List[Dict], Dict]:
    """Full web scan pipeline. Returns: (findings, info)"""

    scan_start = time.time()

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
        verify=False,
        timeout=httpx.Timeout(connect=6.0, read=12.0, write=6.0, pool=5.0),
    ) as client:

        all_findings: List[Dict] = []

        # Info gathering
        gatherer = InfoGatherer()
        info     = await gatherer.gather(url, client)

        # ── Security headers on main URL ──────────────────────────────────────
        header_scanner = HeadersScanner()
        header_findings, csp_value = await header_scanner.test_url(url, client)
        all_findings.extend(header_findings)

        if csp_value:
            print("[Permi] CSP detected — XSS findings will include CSP context for accurate AI analysis.")

        # ── JS crawl ──────────────────────────────────────────────────────────
        if use_js:
            info["scan_mode"] = "js"
            from scanner.js_crawler import JSCrawler
            js_crawler = JSCrawler(
                base_url           = url,
                max_pages          = min(max_pages, 15),  # community limit
                include_subdomains = include_subdomains,
                max_minutes        = 5,
                page_timeout_ms    = page_timeout_ms,
            )
            crawl_result = await js_crawler.crawl()

            # BULLETPROOF: Handle any return format from js_crawler
            unique_parameterised = []
            api_endpoints        = []
            all_urls_js          = set()

            if isinstance(crawl_result, tuple):
                if len(crawl_result) >= 3:
                    # Format: (unique, api_endpoints, all_urls_or_flag)
                    if isinstance(crawl_result[0], list):
                        unique_parameterised = crawl_result[0]
                    if isinstance(crawl_result[1], list):
                        api_endpoints = crawl_result[1]
                    # 3rd element could be all_urls (set) or True (bool)
                    if len(crawl_result) >= 3 and isinstance(crawl_result[2], (set, list)):
                        all_urls_js = set(crawl_result[2])
                elif len(crawl_result) == 2:
                    # Format: (unique, api_endpoints)
                    if isinstance(crawl_result[0], list):
                        unique_parameterised = crawl_result[0]
                    if isinstance(crawl_result[1], list):
                        api_endpoints = crawl_result[1]

            all_urls = set(unique_parameterised + api_endpoints) | all_urls_js
            info["urls_discovered"] = len(all_urls)
            pages_rendered = getattr(js_crawler, 'pages_rendered', len(unique_parameterised))
            print(
                f"[Permi JS] Crawl complete — {pages_rendered} pages rendered, "
                f"{len(all_urls)} URLs found, "
                f"{len(unique_parameterised)} unique parameter signatures to test"
            )

        # ── HTTP crawl ────────────────────────────────────────────────────────
        else:
            info["scan_mode"] = "http"
            crawler  = WebCrawler(url, max_pages=max_pages, include_subdomains=include_subdomains)
            all_urls, is_spa = await crawler.crawl(client)

            if is_spa and len([u for u in all_urls if "?" in u]) == 0:
                print()
                print("[Permi] ⚠️  JavaScript-rendered application detected.")
                print(f"[Permi]    Crawler found {len(all_urls)} URL(s) but 0 with parameters to test.")
                print("[Permi]    This site renders content with React, Vue, or Angular.")
                print("[Permi]    The HTTP crawler cannot see JavaScript-rendered links and forms.")
                print("[Permi]    Header findings below are still accurate and complete.")
                print("[Permi]    Re-run with --js to scan the full JavaScript-rendered content:")
                print(f"[Permi]      permi scan --url {url} --js")
                print()

            # Print progress before testing
            unique_parameterised = _dedup_urls([u for u in all_urls if "?" in u])
            print(f"[Permi] {len(all_urls)} URLs discovered → {len(unique_parameterised)} unique parameter signatures to test")

        # ── SQL + XSS on parameterised URLs ───────────────────────────────────
        sql_scanner = SQLInjectionScanner(client)
        xss_scanner = XSSScanner(client)

        param_urls = _dedup_urls([u for u in all_urls if "?" in u])
        total      = len(param_urls)

        for i, target_url in enumerate(param_urls, 1):
            short = (target_url[:70] + "...") if len(target_url) > 70 else target_url
            print(f"[Permi] Testing {i}/{total}: {short}", flush=True)
            try:
                findings = await asyncio.wait_for(
                    _scan_single_url(target_url, sql_scanner, xss_scanner, csp_value),
                    timeout=60.0,
                )
                all_findings.extend(findings)
            except asyncio.TimeoutError:
                print(f"[Permi] Timeout on scan: {short[:60]} — skipping")
            except Exception:
                pass

            await asyncio.sleep(0.15)

    # ── Deduplication ─────────────────────────────────────────────────────────
    # Same (url, parameter, rule_id) should only appear once.
    seen    = set()
    deduped = []
    for f in all_findings:
        key = (
            f.get("file", ""),
            f.get("parameter", ""),
            f.get("rule_id", ""),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # ── Scan timer ────────────────────────────────────────────────────────────
    elapsed_secs = int(time.time() - scan_start)
    info["scan_duration"] = f"{elapsed_secs // 60}m {elapsed_secs % 60}s" if elapsed_secs >= 60 else f"{elapsed_secs}s"
    info["urls_discovered"] = info.get("urls_discovered", len(all_urls))
    info["urls_tested"]     = len(param_urls)

    return deduped, info


def scan_url(
    url:                str,
    max_pages:          int  = 30,
    include_subdomains: bool = False,
    use_js:             bool = False,
    page_timeout_ms:    int  = 20000,
) -> Tuple[List[Dict], Dict]:
    """
    Synchronous entry point for web scanning.
    Called by cli/main.py when --url flag is used.
    """
    return asyncio.run(
        _run_web_scan(
            url,
            max_pages          = max_pages,
            include_subdomains = include_subdomains,
            use_js             = use_js,
            page_timeout_ms    = page_timeout_ms,
        )
    )
