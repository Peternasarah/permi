"""
scanner/web_scanner.py
Web vulnerability scanner — HTTP-based active scanning engine.
Handles: SQL injection, XSS, security headers, info gathering, crawling.
Used by: permi scan --url https://target.com
"""

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
    "Permi Security Scanner/0.1 "
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
    "error_based": ["'", '"', "\\", ";", "'--", "'/*"],
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

SKIP_DIRS = {
    "node_modules", "venv", ".venv", "__pycache__",
    ".git", "dist", "build", ".next",
}


# ── SQL INJECTION SCANNER ─────────────────────────────────────────────────────
class SQLInjectionScanner:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def test_url(self, url: str) -> List[Dict]:
        """Test all URL parameters for SQL injection."""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param, values in params.items():
            original_value = values[0] if values else ""

            # Error-based detection
            findings.extend(
                await self._test_error_based(base_url, param, original_value, params)
            )
            # Boolean-based detection
            findings.extend(
                await self._test_boolean_based(base_url, param, original_value, params)
            )
            # Time-based detection
            findings.extend(
                await self._test_time_based(base_url, param, original_value, params)
            )

        return findings

    async def _test_error_based(
        self, base_url: str, param: str, value: str, params: dict
    ) -> List[Dict]:
        findings = []
        for payload in SQL_PAYLOADS["error_based"]:
            test_params = {k: v for k, v in params.items()}
            test_params[param] = [value + payload]
            try:
                response = await self.client.get(
                    base_url, params=test_params, timeout=10
                )
                lower = response.text.lower()
                for error in SQL_ERRORS:
                    if error in lower:
                        findings.append({
                            "rule_id":      "WEB_SQL001",
                            "rule_name":    "SQL Injection — Error-based",
                            "severity":     "high",
                            "description": (
                                "A SQL error was returned when a special character "
                                f"was injected into parameter '{param}'. "
                                "This indicates unsanitised input is passed directly "
                                "to a database query."
                            ),
                            "file":         base_url,
                            "line_number":  0,
                            "line_content": f"?{param}={value}{payload}",
                            "parameter":    param,
                            "payload":      payload,
                            "evidence":     f"DB error: {error}",
                            "ai_verdict":   None,
                            "ai_explanation": None,
                        })
                        return findings
            except Exception:
                continue
        return findings

    async def _test_boolean_based(
        self, base_url: str, param: str, value: str, params: dict
    ) -> List[Dict]:
        findings = []
        try:
            baseline = await self.client.get(
                base_url, params=params, timeout=10
            )
            baseline_len = len(baseline.text)

            for payload in SQL_PAYLOADS["boolean_based"][:3]:
                test_params = {k: v for k, v in params.items()}
                test_params[param] = [value + payload]
                try:
                    resp_true = await self.client.get(
                        base_url, params=test_params, timeout=10
                    )
                    # Verify with a FALSE condition
                    false_payload = payload.replace("'1'='1'", "'1'='2'").replace("1=1", "1=2")
                    test_params[param] = [value + false_payload]
                    resp_false = await self.client.get(
                        base_url, params=test_params, timeout=10
                    )

                    true_len  = len(resp_true.text)
                    false_len = len(resp_false.text)

                    # Significant diff between TRUE and FALSE → blind SQLi
                    if abs(true_len - false_len) > 50 and abs(true_len - baseline_len) > 30:
                        findings.append({
                            "rule_id":      "WEB_SQL002",
                            "rule_name":    "SQL Injection — Boolean-based Blind",
                            "severity":     "high",
                            "description": (
                                f"Parameter '{param}' produces significantly different "
                                "responses for true vs false SQL conditions, indicating "
                                "boolean-based blind SQL injection."
                            ),
                            "file":         base_url,
                            "line_number":  0,
                            "line_content": f"?{param}={value}{payload}",
                            "parameter":    param,
                            "payload":      payload,
                            "evidence": (
                                f"TRUE response: {true_len} bytes, "
                                f"FALSE response: {false_len} bytes, "
                                f"baseline: {baseline_len} bytes"
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

    async def _test_time_based(
        self, base_url: str, param: str, value: str, params: dict
    ) -> List[Dict]:
        findings = []
        try:
            start = time.time()
            await self.client.get(base_url, params=params, timeout=10)
            baseline_time = time.time() - start

            for payload in SQL_PAYLOADS["time_based"]:
                test_params = {k: v for k, v in params.items()}
                test_params[param] = [value + payload]
                try:
                    start = time.time()
                    await self.client.get(
                        base_url, params=test_params, timeout=15
                    )
                    elapsed = time.time() - start

                    if elapsed > baseline_time + 4:
                        findings.append({
                            "rule_id":      "WEB_SQL003",
                            "rule_name":    "SQL Injection — Time-based Blind",
                            "severity":     "high",
                            "description": (
                                f"Parameter '{param}' caused a significant response delay "
                                "when a time-delay SQL payload was injected, indicating "
                                "time-based blind SQL injection."
                            ),
                            "file":         base_url,
                            "line_number":  0,
                            "line_content": f"?{param}={value}{payload}",
                            "parameter":    param,
                            "payload":      payload,
                            "evidence": (
                                f"Response time: {elapsed:.2f}s "
                                f"(baseline: {baseline_time:.2f}s)"
                            ),
                            "ai_verdict":     None,
                            "ai_explanation": None,
                        })
                        return findings
                except asyncio.TimeoutError:
                    findings.append({
                        "rule_id":      "WEB_SQL003",
                        "rule_name":    "SQL Injection — Time-based Blind",
                        "severity":     "high",
                        "description": (
                            f"Parameter '{param}' caused a request timeout "
                            "when a time-delay SQL payload was injected."
                        ),
                        "file":         base_url,
                        "line_number":  0,
                        "line_content": f"?{param}={value}{payload}",
                        "parameter":    param,
                        "payload":      payload,
                        "evidence":     "Request timed out (>15s)",
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
        """Test all URL parameters for reflected XSS."""
        findings = []
        parsed   = urlparse(url)
        params   = parse_qs(parsed.query)

        if not params:
            return findings

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param, values in params.items():
            original = values[0] if values else ""

            # First check if the parameter reflects at all
            marker = f"permi_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
            test_params = {k: v for k, v in params.items()}
            test_params[param] = [marker]

            try:
                probe = await self.client.get(
                    base_url, params=test_params, timeout=10
                )
                if marker not in probe.text:
                    continue  # Parameter doesn't reflect — skip XSS for this param

                # Reflected — now test actual XSS payloads
                for payload in XSS_PAYLOADS:
                    test_params[param] = [payload]
                    try:
                        xss_resp = await self.client.get(
                            base_url, params=test_params, timeout=10
                        )
                        if self._is_reflected_unencoded(xss_resp.text, payload):
                            findings.append({
                                "rule_id":      "WEB_XSS001",
                                "rule_name":    "XSS — Reflected Cross-Site Scripting",
                                "severity":     "high",
                                "description": (
                                    f"Parameter '{param}' reflects user input "
                                    "into the page without HTML encoding. "
                                    "An attacker can inject malicious scripts "
                                    "that execute in a victim's browser."
                                ),
                                "file":         base_url,
                                "line_number":  0,
                                "line_content": f"?{param}={payload}",
                                "parameter":    param,
                                "payload":      payload,
                                "evidence":     "Payload reflected unencoded in response",
                                "ai_verdict":     None,
                                "ai_explanation": None,
                            })
                            break  # One finding per parameter is enough
                    except Exception:
                        continue

            except Exception:
                continue

        return findings

    def _is_reflected_unencoded(self, html: str, payload: str) -> bool:
        """Return True if payload appears in HTML without encoding."""
        if "&lt;" in html and "<script" in payload.lower():
            return False  # Encoded — safe
        return payload.lower() in html.lower() or "<script" in html.lower()


# ── SECURITY HEADERS SCANNER ──────────────────────────────────────────────────
class HeadersScanner:
    async def test_url(self, url: str, client: httpx.AsyncClient) -> List[Dict]:
        """Check for missing or weak security headers."""
        findings = []
        try:
            response = await client.get(url, timeout=10)
            headers  = {k.lower(): v for k, v in response.headers.items()}

            missing = []
            for h in SECURITY_HEADERS:
                if h.lower() not in headers:
                    missing.append(h)

            if missing:
                findings.append({
                    "rule_id":      "WEB_HDR001",
                    "rule_name":    "Missing Security Headers",
                    "severity":     "medium",
                    "description": (
                        "The server response is missing one or more recommended "
                        "security headers. These headers protect users from common "
                        "browser-based attacks including clickjacking, MIME sniffing, "
                        "and cross-site scripting."
                    ),
                    "file":         url,
                    "line_number":  0,
                    "line_content": f"Missing: {', '.join(missing)}",
                    "evidence":     f"Missing headers: {', '.join(missing)}",
                    "ai_verdict":     None,
                    "ai_explanation": None,
                })

            # Check for information disclosure via headers
            for header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
                if header.lower() in headers:
                    findings.append({
                        "rule_id":      "WEB_HDR002",
                        "rule_name":    "Server Information Disclosure",
                        "severity":     "low",
                        "description": (
                            f"The '{header}' response header exposes server "
                            "technology and version information. Attackers can "
                            "use this to identify known vulnerabilities."
                        ),
                        "file":         url,
                        "line_number":  0,
                        "line_content": f"{header}: {headers[header.lower()]}",
                        "evidence":     f"{header}: {headers[header.lower()]}",
                        "ai_verdict":     None,
                        "ai_explanation": None,
                    })

        except Exception:
            pass

        return findings


# ── INFO GATHERING ────────────────────────────────────────────────────────────
class InfoGatherer:
    async def gather(self, url: str, client: httpx.AsyncClient) -> Dict:
        """Gather basic target information."""
        info = {"target": url, "timestamp": datetime.now().isoformat()}

        parsed = urlparse(url)
        domain = parsed.netloc

        try:
            ip = socket.gethostbyname(domain)
            info["ip"] = ip
        except Exception:
            info["ip"] = "Could not resolve"

        try:
            response = await client.get(url, timeout=10)
            info["status_code"] = response.status_code
            info["server"]      = response.headers.get("Server", "Not disclosed")
            info["powered_by"]  = response.headers.get("X-Powered-By", "Not disclosed")
            info["content_type"] = response.headers.get("Content-Type", "Unknown")

            # Check SSL
            info["https"] = url.startswith("https://")

        except Exception as e:
            info["error"] = str(e)

        return info


# ── WEB CRAWLER ───────────────────────────────────────────────────────────────
class WebCrawler:
    def __init__(self, base_url: str, max_pages: int = 30):
        self.base_url  = base_url
        self.max_pages = max_pages

    async def crawl(self, client: httpx.AsyncClient) -> Set[str]:
        """Crawl the target and return discovered URLs."""
        visited    = set()
        to_visit   = deque([self.base_url])
        discovered = set([self.base_url])
        base_domain = urlparse(self.base_url).netloc

        while to_visit and len(visited) < self.max_pages:
            url = to_visit.popleft()

            if url in visited:
                continue

            visited.add(url)

            try:
                response = await client.get(url, timeout=10)
                soup = BeautifulSoup(response.text, "html.parser")

                # Extract all links
                for tag in soup.find_all(["a", "form"], href=True):
                    href = tag.get("href") or tag.get("action", "")
                    full = urljoin(url, href)

                    # Stay on same domain
                    if urlparse(full).netloc == base_domain and full not in visited:
                        discovered.add(full)
                        to_visit.append(full)

                await asyncio.sleep(0.3)  # polite rate limit

            except Exception:
                continue

        return discovered


# ── MAIN WEB SCAN ORCHESTRATOR ────────────────────────────────────────────────
async def _run_web_scan(url: str, max_pages: int = 30) -> tuple[List[Dict], Dict]:
    """
    Run the full web scan pipeline:
    1. Info gathering
    2. Crawl
    3. SQL injection testing on all discovered URLs
    4. XSS testing on all discovered URLs
    5. Security headers check

    Returns: (findings, info)
    """
    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
        verify=False,      # Common in pentest tools — targets may have self-signed certs
        timeout=15,
    ) as client:

        all_findings: List[Dict] = []

        # ── 1. Info gathering ─────────────────────────────────────────────────
        gatherer = InfoGatherer()
        info     = await gatherer.gather(url, client)

        # ── 2. Crawl ──────────────────────────────────────────────────────────
        crawler  = WebCrawler(url, max_pages=max_pages)
        all_urls = await crawler.crawl(client)

        # ── 3. Security headers (on main URL only) ────────────────────────────
        header_scanner = HeadersScanner()
        header_findings = await header_scanner.test_url(url, client)
        all_findings.extend(header_findings)

        # ── 4. SQL + XSS on all discovered URLs ───────────────────────────────
        sql_scanner = SQLInjectionScanner(client)
        xss_scanner = XSSScanner(client)

        for target_url in all_urls:
            # Only test URLs that have query parameters
            if "?" not in target_url:
                continue

            sql_findings = await sql_scanner.test_url(target_url)
            all_findings.extend(sql_findings)

            xss_findings = await xss_scanner.test_url(target_url)
            all_findings.extend(xss_findings)

            await asyncio.sleep(0.2)  # polite rate limit

    info["urls_discovered"] = len(all_urls)
    info["urls_tested"]     = len([u for u in all_urls if "?" in u])

    return all_findings, info


def scan_url(url: str, max_pages: int = 30) -> tuple[List[Dict], Dict]:
    """
    Synchronous entry point for web scanning.
    Called by cli/main.py when --url flag is used.
    Returns (findings, info_dict)
    """
    return asyncio.run(_run_web_scan(url, max_pages=max_pages))
