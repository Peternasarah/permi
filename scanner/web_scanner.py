# scanner/web_scanner.py  — v0.3 (all fixes applied)
# Web vulnerability scanner — HTTP-based active scanning engine.
#


from __future__ import annotations

import asyncio
import socket
import re
import time
import json
import hashlib
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urlparse, urljoin, parse_qs
from collections import deque
from datetime import datetime

import httpx
from bs4 import BeautifulSoup


USER_AGENT = (
    "Permi Security Scanner/0.3 "
    "(github.com/Peternasarah/permi; authorized security testing only)"
)

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

SQL_PAYLOADS = {
    "error_based":   ["'", '"', "\\", ";", "'--", "'/*"],
    "boolean_based": ["' OR '1'='1'"],      # one payload — 67% fewer requests
    "time_based":    ["'; SELECT SLEEP(5)--"],  # MySQL only
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

# Response sizes that indicate redirect/error pages not SQLi
KNOWN_FP_SIZES = {9593, 285, 118, 1523}

# params that are structurally redirect targets, never reflective
LIKELY_NON_REFLECTIVE_PARAMS = {
    "next", "redirect", "redirect_to", "return", "callback",
    "state", "nonce", "csrf", "token", "_token",
}

# JS framework signals
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
    if len(parts) >= 3:
        if ".".join(parts[-2:]) in two_part_tlds:
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


# ── CSP HELPERS ────────────────────────────────────────────────────────
def _csp_blocks_inline(csp: Optional[str]) -> bool:
    """
    Return True if the CSP header blocks inline script execution.
    A CSP with script-src that lacks 'unsafe-inline' prevents alert()
    from executing even when the payload is reflected in the response.
    """
    if not csp:
        return False
    csp_lower = csp.lower()
    if "script-src" in csp_lower:
        if "unsafe-inline" not in csp_lower and "'*'" not in csp_lower:
            return True
    if "default-src" in csp_lower and "script-src" not in csp_lower:
        if "unsafe-inline" not in csp_lower and "'*'" not in csp_lower:
            return True
    return False


# ──  URL DEDUPLICATION ──────────────────────────────────────────────────
def _dedup_urls(urls: Set[str]) -> List[str]:
    """
    Return unique parameterised URLs keyed by (netloc, path, param-names).
    /contact?ref_cta=A and /contact?ref_cta=B share the same signature.
    Only one is tested — eliminates duplicate findings per endpoint.
    """
    seen:   set       = set()
    unique: List[str] = []
    for url in urls:
        if "?" not in url:
            continue
        parsed = urlparse(url)
        sig    = (parsed.netloc, parsed.path, frozenset(parse_qs(parsed.query).keys()))
        if sig not in seen:
            seen.add(sig)
            unique.append(url)
    return unique


# ── SPA DETECTION ──────────────────────────────────────────────────────
def _detect_spa(html: str) -> bool:
    """
    Detect JavaScript-rendered single-page applications.
    Returns True if 2+ framework signatures are present OR the page
    is large but contains almost no crawlable links (SPA shell pattern).
    """
    lower = html.lower()
    hits  = sum(1 for sig in JS_FRAMEWORK_SIGNATURES if sig in lower)
    if hits >= 2:
        return True
    soup         = BeautifulSoup(html, "html.parser")
    crawlable    = soup.find_all("a", href=True)
    page_is_long = len(html) > 5000
    if page_is_long and len(crawlable) < 3:
        return True
    return False


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
            original = values[0] if values else ""
            findings.extend(await self._test_error_based(base_url, param, original, params))
            findings.extend(await self._test_boolean_based(base_url, param, original, params))
            findings.extend(await self._test_time_based(base_url, param, original, params))
        return findings

    async def _test_error_based(self, base_url, param, value, params):
        findings = []
        for payload in SQL_PAYLOADS["error_based"]:
            test_params        = {k: v for k, v in params.items()}
            test_params[param] = [value + payload]
            try:
                response = await self.client.get(base_url, params=test_params, timeout=8)
                lower    = response.text.lower()
                for error in SQL_ERRORS:
                    if error in lower:
                        findings.append({
                            "rule_id":        "WEB_SQL001",
                            "rule_name":      "SQL Injection — Error-based",
                            "severity":       "high",
                            "description":    f"A SQL error was returned when a special character was injected into parameter '{param}'.",
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
            baseline     = await self.client.get(base_url, params=params, timeout=8)
            baseline_len = len(baseline.text)

            payload       = "' OR '1'='1'"
            false_payload = "' OR '1'='2'"

            tp               = {k: v for k, v in params.items()}
            tp[param]        = [value + payload]
            fp               = {k: v for k, v in params.items()}
            fp[param]        = [value + false_payload]

            try:
                rt = await self.client.get(base_url, params=tp, timeout=8)
                rf = await self.client.get(base_url, params=fp, timeout=8)
                tl = len(rt.text)
                fl = len(rf.text)

                if tl in KNOWN_FP_SIZES or fl in KNOWN_FP_SIZES:
                    return findings

                if abs(tl - fl) > 200 and abs(tl - baseline_len) > 100:
                    findings.append({
                        "rule_id":        "WEB_SQL002",
                        "rule_name":      "SQL Injection — Boolean-based Blind",
                        "severity":       "high",
                        "description":    f"Parameter '{param}' produces different responses for true/false SQL conditions.",
                        "file":           base_url,
                        "line_number":    0,
                        "line_content":   f"?{param}={value}{payload}",
                        "parameter":      param,
                        "payload":        payload,
                        "evidence":       f"TRUE: {tl}b, FALSE: {fl}b, baseline: {baseline_len}b",
                        "ai_verdict":     None,
                        "ai_explanation": None,
                    })
            except Exception:
                pass
        except Exception:
            pass
        return findings

    async def _test_time_based(self, base_url, param, value, params):
        findings = []
        try:
            start         = time.time()
            await asyncio.wait_for(self.client.get(base_url, params=params), timeout=8.0)
            baseline_time = time.time() - start

            payload            = "'; SELECT SLEEP(5)--"
            tp                 = {k: v for k, v in params.items()}
            tp[param]          = [value + payload]

            try:
                start = time.time()
                await asyncio.wait_for(self.client.get(base_url, params=tp), timeout=10.0)
                elapsed = time.time() - start

                if elapsed > baseline_time + 6:
                    findings.append({
                        "rule_id":        "WEB_SQL003",
                        "rule_name":      "SQL Injection — Time-based Blind",
                        "severity":       "high",
                        "description":    f"Parameter '{param}' caused a significant delay with a time-delay payload.",
                        "file":           base_url,
                        "line_number":    0,
                        "line_content":   f"?{param}={value}{payload}",
                        "parameter":      param,
                        "payload":        payload,
                        "evidence":       f"Response: {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                        "ai_verdict":     None,
                        "ai_explanation": None,
                    })
            except asyncio.TimeoutError:
                pass  # timeout ≠ evidence; could be CDN rate limiting
            except Exception:
                pass
        except Exception:
            pass
        return findings


# ── XSS SCANNER ───────────────────────────────────────────────────────────────
class XSSScanner:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def test_url(self, url: str, csp: Optional[str] = None) -> List[Dict]:
        """
        FIX A: csp parameter carries the target's Content-Security-Policy
        value into every XSS finding. The AI uses it to decide whether
        reflected input is actually exploitable in a browser context.
        """
        findings   = []
        parsed     = urlparse(url)
        params     = parse_qs(parsed.query)
        if not params:
            return findings

        base_url   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        csp_blocks = _csp_blocks_inline(csp)

        for param, values in params.items():
            if param.lower() in LIKELY_NON_REFLECTIVE_PARAMS:
                continue

            marker      = f"permi_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
            test_params = {k: v for k, v in params.items()}
            test_params[param] = [marker]

            try:
                probe = await self.client.get(base_url, params=test_params, timeout=8)
                if marker not in probe.text:
                    continue

                for payload in XSS_PAYLOADS:
                    test_params[param] = [payload]
                    try:
                        resp = await self.client.get(base_url, params=test_params, timeout=8)
                        if self._is_reflected_unencoded(resp.text, payload):

                            
                            if csp_blocks:
                                description = (
                                    f"Parameter '{param}' reflects input without HTML encoding. "
                                    f"CSP present — browser execution may be blocked."
                                )
                                evidence = (
                                    f"Payload reflected unencoded. "
                                    f"CSP: {(csp or '')[:120]}"
                                )
                            else:
                                description = f"Parameter '{param}' reflects user input without HTML encoding."
                                evidence    = "Payload reflected unencoded in response"

                            findings.append({
                                "rule_id":           "WEB_XSS001",
                                "rule_name":         "XSS — Reflected Cross-Site Scripting",
                                "severity":          "high",
                                "description":       description,
                                "file":              base_url,
                                "line_number":       0,
                                "line_content":      f"?{param}={payload}",
                                "parameter":         param,
                                "payload":           payload,
                                "evidence":          evidence,
                                # FIX A: AI reads these fields for accurate verdict
                                "csp":               csp or "not present",
                                "csp_blocks_inline": csp_blocks,
                                "ai_verdict":        None,
                                "ai_explanation":    None,
                            })
                            break
                    except Exception:
                        continue
            except Exception:
                continue

        return findings

    def _is_reflected_unencoded(self, html: str, payload: str) -> bool:
        if "&lt;" in html and "<script" in payload.lower():
            return False
        return payload.lower() in html.lower() or "<script" in html.lower()


# ── SECURITY HEADERS SCANNER ──────────────────────────────────────────────────
class HeadersScanner:
    async def test_url(
        self, url: str, client: httpx.AsyncClient
    ) -> Tuple[List[Dict], Optional[str]]:
        """
        FIX A: Returns (findings, csp_value).
        The csp_value is passed to the XSSScanner and into each XSS finding
        so the AI has full context when evaluating exploitability.
        """
        findings:  List[Dict]    = []
        csp_value: Optional[str] = None

        try:
            response  = await client.get(url, timeout=8)
            headers   = {k.lower(): v for k, v in response.headers.items()}
            csp_value = headers.get("content-security-policy", None)

            missing = [h for h in SECURITY_HEADERS if h.lower() not in headers]
            if missing:
                findings.append({
                    "rule_id":        "WEB_HDR001",
                    "rule_name":      "Missing Security Headers",
                    "severity":       "medium",
                    "description":    "The server is missing recommended security headers.",
                    "file":           url,
                    "line_number":    0,
                    "line_content":   f"Missing: {', '.join(missing)}",
                    "evidence":       f"Missing headers: {', '.join(missing)}",
                    "ai_verdict":     None,
                    "ai_explanation": None,
                })

            for header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
                if header.lower() in headers:
                    findings.append({
                        "rule_id":        "WEB_HDR002",
                        "rule_name":      "Server Information Disclosure",
                        "severity":       "low",
                        "description":    f"The '{header}' header exposes server technology.",
                        "file":           url,
                        "line_number":    0,
                        "line_content":   f"{header}: {headers[header.lower()]}",
                        "evidence":       f"{header}: {headers[header.lower()]}",
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
            info["ip"] = socket.gethostbyname(domain)
        except Exception:
            info["ip"] = "Could not resolve"

        try:
            response            = await client.get(url, timeout=8)
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
        """
        FIX C: Returns (discovered_urls, is_spa).
        is_spa=True triggers a clear warning with --js roadmap hint.
        """
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
                response = await asyncio.wait_for(
                    client.get(url, timeout=8),
                    timeout=10.0
                )
                html = response.text

                # FIX C: detect SPA on home page only
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

                await asyncio.sleep(0.1)   # was 0.3

            except (asyncio.TimeoutError, Exception):
                continue

        return discovered, is_spa


# ── FIX B: CONCURRENT PER-URL SCANNER ────────────────────────────────────────
async def _scan_single_url(
    target_url:  str,
    sql_scanner: SQLInjectionScanner,
    xss_scanner: XSSScanner,
    csp:         Optional[str],
) -> List[Dict]:
    """
    FIX B: SQL and XSS run concurrently via asyncio.gather().
    Previously: SQL finished → then XSS started. Each URL took ~2× longer.
    Now: both run in parallel → ~50% faster per URL.
    """
    sql_task = asyncio.wait_for(sql_scanner.test_url(target_url), timeout=45.0)
    xss_task = asyncio.wait_for(xss_scanner.test_url(target_url, csp=csp), timeout=30.0)

    results  = await asyncio.gather(sql_task, xss_task, return_exceptions=True)
    findings = []
    for result in results:
        if not isinstance(result, Exception):
            findings.extend(result)
    return findings


# ── MAIN WEB SCAN ORCHESTRATOR ────────────────────────────────────────────────
async def _run_web_scan(
    url:                str,
    max_pages:          int  = 30,
    include_subdomains: bool = False,
) -> Tuple[List[Dict], Dict]:

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
        verify=False,
        timeout=httpx.Timeout(connect=6.0, read=12.0, write=6.0, pool=5.0),
    ) as client:

        all_findings: List[Dict] = []

        gatherer = InfoGatherer()
        info     = await gatherer.gather(url, client)

        # HeadersScanner now returns CSP value alongside findings
        header_scanner             = HeadersScanner()
        header_findings, csp_value = await header_scanner.test_url(url, client)
        all_findings.extend(header_findings)

        if csp_value:
            print(
                f"[Permi] CSP detected — XSS findings will include "
                f"CSP context for accurate AI analysis."
            )

        # Crawl returns is_spa flag
        crawler          = WebCrawler(url, max_pages=max_pages, include_subdomains=include_subdomains)
        all_urls, is_spa = await crawler.crawl(client)

        # Warn clearly when SPA detected with 0 crawlable param URLs
        if is_spa:
            parameterised = [u for u in all_urls if "?" in u]
            if len(parameterised) == 0:
                print()
                print("[Permi] ⚠️  JavaScript-rendered application detected.")
                print(f"[Permi]    Crawler found {len(all_urls)} URL(s) but 0 with parameters to test.")
                print("[Permi]    This site likely renders content with React, Vue, or Angular.")
                print("[Permi]    Permi's HTTP crawler cannot see JavaScript-rendered links and forms.")
                print("[Permi]    Header findings below are still accurate and complete.")
                print("[Permi]    Full SPA support via Playwright is on the roadmap: permi scan --js")
                print()

        # Deduplicate before scanning
        unique_parameterised = _dedup_urls(all_urls)

        print(
            f"[Permi] {len(all_urls)} URLs discovered → "
            f"{len(unique_parameterised)} unique parameter signatures to test"
        )

        # Concurrent SQL + XSS per URL
        sql_scanner = SQLInjectionScanner(client)
        xss_scanner = XSSScanner(client)

        for target_url in unique_parameterised:
            findings = await _scan_single_url(target_url, sql_scanner, xss_scanner, csp_value)
            all_findings.extend(findings)
            await asyncio.sleep(0.15)

    info["urls_discovered"] = len(all_urls)
    info["urls_tested"]     = len(unique_parameterised)

    return all_findings, info


def scan_url(
    url:                str,
    max_pages:          int  = 30,
    include_subdomains: bool = False,
) -> Tuple[List[Dict], Dict]:
    """Synchronous entry point called by cli/main.py."""
    return asyncio.run(
        _run_web_scan(url, max_pages=max_pages, include_subdomains=include_subdomains)
    )
