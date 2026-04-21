# scanner/web_scanner.py
# Web vulnerability scanner — HTTP-based active scanning engine.
# Handles: SQL injection, XSS, security headers, info gathering, crawling.
# Used by: permi scan --url https://target.com
#
# Subdomain support:
#   Default   — scans the exact domain only (unijos.edu.ng)
#   --include-subdomains — also follows subdomains (portal.unijos.edu.ng)
#   Never follows external domains (google.com, facebook.com etc.)

from __future__ import annotations

import asyncio
import socket
import re
import time
import json
import hashlib
from typing import List, Dict, Set
from urllib.parse import urlparse, urljoin, parse_qs
from collections import deque
from datetime import datetime

import httpx
from bs4 import BeautifulSoup


# ── USER AGENT ────────────────────────────────────────────────────────────────
USER_AGENT = (
    "Permi Security Scanner/0.2 "
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
        "'; WAITFOR DELAY '0:0:5'--",
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


# ── DOMAIN HELPERS ────────────────────────────────────────────────────────────

def _extract_base_domain(netloc: str) -> str:
    """
    Extract the registrable domain from a netloc.
    Examples:
      unijos.edu.ng        → unijos.edu.ng
      portal.unijos.edu.ng → unijos.edu.ng
      www.google.com       → google.com
    """
    # Strip port if present
    host = netloc.split(":")[0].lower()
    parts = host.split(".")

    # Handle common two-part TLDs like .edu.ng, .co.uk, .com.ng, .org.ng
    two_part_tlds = {
        "edu.ng", "co.uk", "com.ng", "org.ng", "gov.ng",
        "net.ng", "com.au", "co.za", "ac.uk", "org.uk",
        "co.nz", "com.br", "co.in",
    }

    if len(parts) >= 3:
        potential_tld = ".".join(parts[-2:])
        if potential_tld in two_part_tlds:
            # e.g. portal.unijos.edu.ng → unijos.edu.ng
            return ".".join(parts[-3:])

    # Standard: take last 2 parts
    # e.g. portal.google.com → google.com
    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return host


def _is_same_scope(url: str, base_domain: str, include_subdomains: bool) -> bool:
    """
    Return True if the URL is within the allowed scanning scope.

    include_subdomains=False  → only exact base_domain matches
    include_subdomains=True   → base_domain AND any subdomain of it
    Never follows completely external domains.
    """
    netloc = urlparse(url).netloc.split(":")[0].lower()

    if not netloc:
        return False

    if include_subdomains:
        # Allow: exact match OR subdomain
        # unijos.edu.ng → True
        # portal.unijos.edu.ng → True
        # google.com → False
        target_base = _extract_base_domain(netloc)
        return target_base == base_domain
    else:
        # Exact match only
        return netloc == base_domain


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
            test_params = {k: v for k, v in params.items()}
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
                                f"A SQL error was returned when a special character "
                                f"was injected into parameter '{param}'."
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

            for payload in SQL_PAYLOADS["boolean_based"][:3]:
                test_params           = {k: v for k, v in params.items()}
                test_params[param]    = [value + payload]
                false_payload         = payload.replace("'1'='1'", "'1'='2'").replace("1=1", "1=2")
                false_params          = {k: v for k, v in params.items()}
                false_params[param]   = [value + false_payload]
                try:
                    resp_true  = await self.client.get(base_url, params=test_params, timeout=10)
                    resp_false = await self.client.get(base_url, params=false_params, timeout=10)
                    true_len   = len(resp_true.text)
                    false_len  = len(resp_false.text)

                    if abs(true_len - false_len) > 50 and abs(true_len - baseline_len) > 30:
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
            await self.client.get(base_url, params=params, timeout=10)
            baseline_time = time.time() - start

            for payload in SQL_PAYLOADS["time_based"]:
                test_params        = {k: v for k, v in params.items()}
                test_params[param] = [value + payload]
                try:
                    start   = time.time()
                    await self.client.get(base_url, params=test_params, timeout=15)
                    elapsed = time.time() - start

                    if elapsed > baseline_time + 4:
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
                        return findings
                except asyncio.TimeoutError:
                    findings.append({
                        "rule_id":        "WEB_SQL003",
                        "rule_name":      "SQL Injection — Time-based Blind",
                        "severity":       "high",
                        "description":    f"Parameter '{param}' caused a request timeout with a time-delay payload.",
                        "file":           base_url,
                        "line_number":    0,
                        "line_content":   f"?{param}={value}{payload}",
                        "parameter":      param,
                        "payload":        payload,
                        "evidence":       "Request timed out (>15s)",
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

    async def test_url(self, url: str) -> List[Dict]:
        findings = []
        parsed   = urlparse(url)
        params   = parse_qs(parsed.query)

        if not params:
            return findings

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param, values in params.items():
            marker      = f"permi_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
            test_params = {k: v for k, v in params.items()}
            test_params[param] = [marker]

            try:
                probe = await self.client.get(base_url, params=test_params, timeout=10)
                if marker not in probe.text:
                    continue

                for payload in XSS_PAYLOADS:
                    test_params[param] = [payload]
                    try:
                        xss_resp = await self.client.get(base_url, params=test_params, timeout=10)
                        if self._is_reflected_unencoded(xss_resp.text, payload):
                            findings.append({
                                "rule_id":        "WEB_XSS001",
                                "rule_name":      "XSS — Reflected Cross-Site Scripting",
                                "severity":       "high",
                                "description":    f"Parameter '{param}' reflects user input without HTML encoding.",
                                "file":           base_url,
                                "line_number":    0,
                                "line_content":   f"?{param}={payload}",
                                "parameter":      param,
                                "payload":        payload,
                                "evidence":       "Payload reflected unencoded in response",
                                "ai_verdict":     None,
                                "ai_explanation": None,
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
    async def test_url(self, url: str, client: httpx.AsyncClient) -> List[Dict]:
        findings = []
        try:
            response = await client.get(url, timeout=10)
            headers  = {k.lower(): v for k, v in response.headers.items()}

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
        return findings


# ── INFO GATHERING ────────────────────────────────────────────────────────────
class InfoGatherer:
    async def gather(self, url: str, client: httpx.AsyncClient) -> Dict:
        info   = {"target": url, "timestamp": datetime.now().isoformat()}
        parsed = urlparse(url)
        domain = parsed.netloc

        try:
            ip = socket.gethostbyname(domain)
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

        # Extract the registrable base domain for scope checks
        netloc           = urlparse(base_url).netloc.split(":")[0].lower()
        self.base_domain = _extract_base_domain(netloc)

    async def crawl(self, client: httpx.AsyncClient) -> Set[str]:
        """
        Crawl the target and return all discovered URLs within scope.

        Scope rules:
          include_subdomains=False → only exact base_domain
          include_subdomains=True  → base_domain + all subdomains
          External domains are NEVER followed.
        """
        visited    = set()
        to_visit   = deque([self.base_url])
        discovered = set([self.base_url])

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
                response = await client.get(url, timeout=10)
                soup     = BeautifulSoup(response.text, "html.parser")

                for tag in soup.find_all(["a", "form"]):
                    href = tag.get("href") or tag.get("action", "")
                    if not href:
                        continue

                    full = urljoin(url, href)

                    # Only follow URLs within scope
                    if (
                        _is_same_scope(full, self.base_domain, self.include_subdomains)
                        and full not in visited
                        and full not in discovered
                    ):
                        discovered.add(full)
                        to_visit.append(full)

                await asyncio.sleep(0.3)

            except Exception:
                continue

        return discovered


# ── MAIN WEB SCAN ORCHESTRATOR ────────────────────────────────────────────────
async def _run_web_scan(
    url:                str,
    max_pages:          int  = 30,
    include_subdomains: bool = False,
) -> tuple[List[Dict], Dict]:
    """
    Full web scan pipeline.
    Returns: (findings, info)
    """
    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
        verify=False,
        timeout=15,
    ) as client:

        all_findings: List[Dict] = []

        # Info gathering
        gatherer = InfoGatherer()
        info     = await gatherer.gather(url, client)

        # Crawl — pass include_subdomains through
        crawler  = WebCrawler(url, max_pages=max_pages, include_subdomains=include_subdomains)
        all_urls = await crawler.crawl(client)

        # Security headers on main URL
        header_scanner  = HeadersScanner()
        header_findings = await header_scanner.test_url(url, client)
        all_findings.extend(header_findings)

        # SQL + XSS on parameterised URLs
        sql_scanner = SQLInjectionScanner(client)
        xss_scanner = XSSScanner(client)

        for target_url in all_urls:
            if "?" not in target_url:
                continue
            all_findings.extend(await sql_scanner.test_url(target_url))
            all_findings.extend(await xss_scanner.test_url(target_url))
            await asyncio.sleep(0.2)

    info["urls_discovered"] = len(all_urls)
    info["urls_tested"]     = len([u for u in all_urls if "?" in u])

    return all_findings, info


def scan_url(
    url:                str,
    max_pages:          int  = 30,
    include_subdomains: bool = False,
) -> tuple[List[Dict], Dict]:
    """
    Synchronous entry point for web scanning.
    Called by cli/main.py when --url flag is used.
    """
    return asyncio.run(
        _run_web_scan(url, max_pages=max_pages, include_subdomains=include_subdomains)
    )
