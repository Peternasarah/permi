# scanner/web_scanner.py

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

USER_AGENT = "Permi Security Scanner/0.4 (github.com/Peternasarah/permi; authorized security testing only)"

SQL_ERRORS = [
    "you have an error in your sql syntax","warning: mysql",
    "unclosed quotation mark","quoted string not properly terminated",
    "sql command not properly ended","postgresql query failed",
    "ora-01756","sqlite3::","microsoft ole db provider for sql server",
    "odbc sql server driver","pg_query","supplied argument is not a valid mysql",
]

SQL_PAYLOADS = {
    "error_based":   ["'",'"',"\\",";","'--","'/*"],
    "boolean_based": ["' OR '1'='1'"],
    "time_based":    ["'; SELECT SLEEP(5)--"],
    "union_based":   ["' UNION SELECT NULL--","' UNION SELECT NULL,NULL--","' UNION SELECT NULL,NULL,NULL--"],
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
    "Strict-Transport-Security","Content-Security-Policy",
    "X-Frame-Options","X-Content-Type-Options",
    "Referrer-Policy","Permissions-Policy",
]

KNOWN_FP_SIZES               = {9593, 285, 118, 1523}
LIKELY_NON_REFLECTIVE_PARAMS = {"next","redirect","redirect_to","return","callback","state","nonce","csrf","token","_token"}
JS_FRAMEWORK_SIGNATURES      = ["react","vue","angular","svelte","next","nuxt","remix","ng-version","__next","__nuxt","data-reactroot","app.bundle.js","main.chunk.js","runtime.js"]


def _extract_base_domain(netloc: str) -> str:
    host  = netloc.split(":")[0].lower()
    parts = host.split(".")
    tlds  = {"edu.ng","co.uk","com.ng","org.ng","gov.ng","net.ng","com.au","co.za","ac.uk","org.uk","co.nz","com.br","co.in"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in tlds:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_same_scope(url: str, base_domain: str, include_subdomains: bool) -> bool:
    netloc = urlparse(url).netloc.split(":")[0].lower()
    if not netloc: return False
    return (_extract_base_domain(netloc) == base_domain) if include_subdomains else (netloc == base_domain)


def _csp_blocks_inline(csp: Optional[str]) -> bool:
    if not csp: return False
    c = csp.lower()
    if "script-src" in c: return "unsafe-inline" not in c and "'*'" not in c
    if "default-src" in c and "script-src" not in c: return "unsafe-inline" not in c and "'*'" not in c
    return False


def _dedup_urls(urls) -> List[str]:
    seen, unique = set(), []
    for url in urls:
        if "?" not in url: continue
        p = urlparse(url); sig = (p.netloc, p.path, frozenset(parse_qs(p.query).keys()))
        if sig not in seen: seen.add(sig); unique.append(url)
    return unique


def _detect_spa(html: str) -> bool:
    lower = html.lower()
    if sum(1 for s in JS_FRAMEWORK_SIGNATURES if s in lower) >= 2: return True
    soup = BeautifulSoup(html, "html.parser")
    return len(html) > 5000 and len(soup.find_all("a", href=True)) < 3


class SQLInjectionScanner:
    def __init__(self, client): self.client = client

    async def test_url(self, url: str) -> List[Dict]:
        findings = []
        p = urlparse(url); params = parse_qs(p.query)
        if not params: return findings
        base = f"{p.scheme}://{p.netloc}{p.path}"
        for param, values in params.items():
            orig = values[0] if values else ""
            findings.extend(await self._error_based(base, param, orig, params))
            findings.extend(await self._boolean_based(base, param, orig, params))
            findings.extend(await self._time_based(base, param, orig, params))
        return findings

    async def _error_based(self, base, param, value, params):
        findings = []
        for payload in SQL_PAYLOADS["error_based"]:
            tp = {**params}; tp[param] = [value + payload]
            try:
                resp = await self.client.get(base, params=tp, timeout=8)
                for err in SQL_ERRORS:
                    if err in resp.text.lower():
                        findings.append({"rule_id":"WEB_SQL001","rule_name":"SQL Injection — Error-based","severity":"high","description":f"SQL error on parameter '{param}'.","file":base,"line_number":0,"line_content":f"?{param}={value}{payload}","parameter":param,"payload":payload,"evidence":f"DB error: {err}","ai_verdict":None,"ai_explanation":None})
                        return findings
            except: continue
        return findings

    async def _boolean_based(self, base, param, value, params):
        findings = []
        try:
            bl = len((await self.client.get(base, params=params, timeout=8)).text)
            tp = {**params}; tp[param] = [value + "' OR '1'='1'"]
            fp = {**params}; fp[param] = [value + "' OR '1'='2'"]
            rt = await self.client.get(base, params=tp, timeout=8)
            rf = await self.client.get(base, params=fp, timeout=8)
            tl, fl = len(rt.text), len(rf.text)
            if tl in KNOWN_FP_SIZES or fl in KNOWN_FP_SIZES: return findings
            if abs(tl - fl) > 200 and abs(tl - bl) > 100:
                findings.append({"rule_id":"WEB_SQL002","rule_name":"SQL Injection — Boolean-based Blind","severity":"high","description":f"Parameter '{param}' produces different true/false responses.","file":base,"line_number":0,"line_content":f"?{param}={value}' OR '1'='1'","parameter":param,"payload":"' OR '1'='1'","evidence":f"TRUE: {tl}b, FALSE: {fl}b, baseline: {bl}b","ai_verdict":None,"ai_explanation":None})
        except: pass
        return findings

    async def _time_based(self, base, param, value, params):
        findings = []
        try:
            t0 = time.time(); await asyncio.wait_for(self.client.get(base, params=params), timeout=8.0); baseline = time.time() - t0
            tp = {**params}; tp[param] = [value + "'; SELECT SLEEP(5)--"]
            try:
                t0 = time.time(); await asyncio.wait_for(self.client.get(base, params=tp), timeout=10.0); elapsed = time.time() - t0
                if elapsed > baseline + 6:
                    findings.append({"rule_id":"WEB_SQL003","rule_name":"SQL Injection — Time-based Blind","severity":"high","description":f"Parameter '{param}' caused a {elapsed:.1f}s delay.","file":base,"line_number":0,"line_content":f"?{param}={value}'; SELECT SLEEP(5)--","parameter":param,"payload":"'; SELECT SLEEP(5)--","evidence":f"Response: {elapsed:.2f}s (baseline: {baseline:.2f}s)","ai_verdict":None,"ai_explanation":None})
            except asyncio.TimeoutError: pass
            except: pass
        except: pass
        return findings


class XSSScanner:
    def __init__(self, client): self.client = client

    async def test_url(self, url: str, csp: Optional[str] = None) -> List[Dict]:
        findings = []
        p = urlparse(url); params = parse_qs(p.query)
        if not params: return findings
        base = f"{p.scheme}://{p.netloc}{p.path}"; csp_blocks = _csp_blocks_inline(csp)
        for param, values in params.items():
            if param.lower() in LIKELY_NON_REFLECTIVE_PARAMS: continue
            marker = f"permi_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
            tp = {**params}; tp[param] = [marker]
            try:
                probe = await self.client.get(base, params=tp, timeout=8)
                if marker not in probe.text: continue
                for payload in XSS_PAYLOADS:
                    tp[param] = [payload]
                    try:
                        resp = await self.client.get(base, params=tp, timeout=8)
                        if self._reflected(resp.text, payload):
                            desc = (f"Parameter '{param}' reflects input without HTML encoding. CSP present — browser execution may be blocked." if csp_blocks else f"Parameter '{param}' reflects user input without HTML encoding.")
                            evid = (f"Payload reflected unencoded. CSP: {(csp or '')[:120]}" if csp_blocks else "Payload reflected unencoded in response")
                            findings.append({"rule_id":"WEB_XSS001","rule_name":"XSS — Reflected Cross-Site Scripting","severity":"high","description":desc,"file":base,"line_number":0,"line_content":f"?{param}={payload}","parameter":param,"payload":payload,"evidence":evid,"csp":csp or "not present","csp_blocks_inline":csp_blocks,"ai_verdict":None,"ai_explanation":None})
                            break
                    except: continue
            except: continue
        return findings

    def _reflected(self, html: str, payload: str) -> bool:
        if "&lt;" in html and "<script" in payload.lower(): return False
        return payload.lower() in html.lower() or "<script" in html.lower()


class HeadersScanner:
    async def test_url(self, url: str, client) -> Tuple[List[Dict], Optional[str]]:
        findings: List[Dict] = []; csp_value: Optional[str] = None
        try:
            resp = await client.get(url, timeout=8)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            csp_value = hdrs.get("content-security-policy", None)
            missing = [h for h in SECURITY_HEADERS if h.lower() not in hdrs]
            if missing:
                findings.append({"rule_id":"WEB_HDR001","rule_name":"Missing Security Headers","severity":"medium","description":"The server is missing recommended security headers.","file":url,"line_number":0,"line_content":f"Missing: {', '.join(missing)}","evidence":f"Missing headers: {', '.join(missing)}","ai_verdict":None,"ai_explanation":None})
            for h in ["Server","X-Powered-By","X-AspNet-Version"]:
                if h.lower() in hdrs:
                    findings.append({"rule_id":"WEB_HDR002","rule_name":"Server Information Disclosure","severity":"low","description":f"The '{h}' header exposes server technology.","file":url,"line_number":0,"line_content":f"{h}: {hdrs[h.lower()]}","evidence":f"{h}: {hdrs[h.lower()]}","ai_verdict":None,"ai_explanation":None})
        except: pass
        return findings, csp_value


class InfoGatherer:
    async def gather(self, url: str, client) -> Dict:
        info = {"target": url, "timestamp": datetime.now().isoformat()}
        parsed = urlparse(url)
        try: info["ip"] = socket.gethostbyname(parsed.netloc)
        except: info["ip"] = "Could not resolve"
        try:
            resp = await client.get(url, timeout=8)
            info.update({"status_code": resp.status_code, "server": resp.headers.get("Server","Not disclosed"), "powered_by": resp.headers.get("X-Powered-By","Not disclosed"), "https": url.startswith("https://")})
        except Exception as e:
            info.update({"error": str(e), "https": url.startswith("https://")})
        return info


class WebCrawler:
    def __init__(self, base_url: str, max_pages: int = 30, include_subdomains: bool = False):
        self.base_url = base_url; self.max_pages = max_pages; self.include_subdomains = include_subdomains
        self.base_domain = _extract_base_domain(urlparse(base_url).netloc.split(":")[0].lower())

    async def crawl(self, client) -> Tuple[Set[str], bool]:
        visited = set(); to_visit = deque([self.base_url]); discovered = set([self.base_url]); is_spa = False
        scope_msg = f"subdomain-aware ({self.base_domain} + subdomains)" if self.include_subdomains else f"exact domain only ({self.base_domain})"
        print(f"[Permi] Scope     : {scope_msg}")
        while to_visit and len(visited) < self.max_pages:
            url = to_visit.popleft()
            if url in visited: continue
            visited.add(url)
            try:
                resp = await asyncio.wait_for(client.get(url, timeout=8), timeout=10.0)
                html = resp.text
                if not is_spa and url == self.base_url: is_spa = _detect_spa(html)
                soup = BeautifulSoup(html, "html.parser")
                for tag in soup.find_all(["a","form"]):
                    href = tag.get("href") or tag.get("action","")
                    if not href: continue
                    full = urljoin(url, href)
                    if _is_same_scope(full, self.base_domain, self.include_subdomains) and full not in visited and full not in discovered:
                        discovered.add(full); to_visit.append(full)
                await asyncio.sleep(0.1)
            except: continue
        return discovered, is_spa


async def _scan_single_url(target_url: str, sql: SQLInjectionScanner, xss: XSSScanner, csp: Optional[str]) -> List[Dict]:
    results = await asyncio.gather(
        asyncio.wait_for(sql.test_url(target_url), timeout=45.0),
        asyncio.wait_for(xss.test_url(target_url, csp=csp), timeout=30.0),
        return_exceptions=True
    )
    findings = []
    for r in results:
        if not isinstance(r, Exception): findings.extend(r)
    return findings


async def _run_web_scan(
    url:                str,
    max_pages:          int  = 30,
    include_subdomains: bool = False,
    use_js:             bool = False,
    page_timeout_ms:    int  = 20000,   # CHANGE: passed from --js-timeout × 1000
) -> Tuple[List[Dict], Dict]:

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT}, follow_redirects=True, verify=False,
        timeout=httpx.Timeout(connect=6.0, read=12.0, write=6.0, pool=5.0),
    ) as client:

        all_findings: List[Dict] = []
        info = await InfoGatherer().gather(url, client)
        header_findings, csp_value = await HeadersScanner().test_url(url, client)
        all_findings.extend(header_findings)

        if csp_value:
            print("[Permi] CSP detected — XSS findings will include CSP context for accurate AI analysis.")

        if use_js:
            from scanner.js_crawler import JSCrawler
            js_crawler = JSCrawler(
                base_url           = url,
                max_pages          = min(max_pages, 15),
                include_subdomains = include_subdomains,
                max_minutes        = 5,
                page_timeout_ms    = page_timeout_ms,   # CHANGE: --js-timeout × 1000
            )
            unique_parameterised, api_endpoints, _ = await js_crawler.crawl()
            all_urls = set(unique_parameterised + api_endpoints)
            info.update({"urls_discovered": len(all_urls), "urls_tested": len(unique_parameterised), "scan_mode": "js"})

        else:
            crawler = WebCrawler(url, max_pages=max_pages, include_subdomains=include_subdomains)
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

            unique_parameterised = _dedup_urls(all_urls)
            info.update({"urls_discovered": len(all_urls), "urls_tested": len(unique_parameterised), "scan_mode": "http"})
            print(f"[Permi] {len(all_urls)} URLs discovered → {len(unique_parameterised)} unique parameter signatures to test")

        sql_scanner = SQLInjectionScanner(client)
        xss_scanner = XSSScanner(client)
        for target_url in unique_parameterised:
            all_findings.extend(await _scan_single_url(target_url, sql_scanner, xss_scanner, csp_value))
            await asyncio.sleep(0.15)

    return all_findings, info


def scan_url(
    url:                str,
    max_pages:          int  = 30,
    include_subdomains: bool = False,
    use_js:             bool = False,
    page_timeout_ms:    int  = 20000,   # CHANGE: from --js-timeout × 1000
) -> Tuple[List[Dict], Dict]:
    return asyncio.run(
        _run_web_scan(
            url,
            max_pages          = max_pages,
            include_subdomains = include_subdomains,
            use_js             = use_js,
            page_timeout_ms    = page_timeout_ms,
        )
    )
