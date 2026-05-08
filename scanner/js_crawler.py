# scanner/js_crawler.py
# Playwright-based JavaScript crawler for Permi.
# Handles React, Vue, Angular, Next.js, Nuxt, and any SPA.
#
# Used when: permi scan --url https://target.com --js
#
# INSTALL REQUIREMENT:
#   pip install playwright
#   playwright install chromium
#
# HOW IT WORKS:
#   1. Launches headless Chromium browser
#   2. Navigates to the target URL and waits for full JS render
#   3. Intercepts all XHR/fetch network requests (finds API endpoints)
#   4. Clicks interactive elements to reveal dynamic content
#   5. Extracts all links, forms, inputs from the live DOM
#   6. Returns parameterised URLs ready for SQLi/XSS scanning
#   7. Shuts down the browser cleanly

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Set, List, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin, urlencode, parse_qs


# ── PLAYWRIGHT AVAILABILITY CHECK ─────────────────────────────────────────────
def playwright_available() -> bool:
    """Check if Playwright is installed without importing it at module level."""
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def chromium_installed() -> bool:
    """Check if the Chromium browser binary is installed."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


# ── DOMAIN SCOPE HELPERS ──────────────────────────────────────────────────────
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


def _in_scope(url: str, base_domain: str, include_subdomains: bool) -> bool:
    try:
        netloc = urlparse(url).netloc.split(":")[0].lower()
        if not netloc:
            return False
        if include_subdomains:
            return _extract_base_domain(netloc) == base_domain
        return netloc == base_domain
    except Exception:
        return False


# ── URL DEDUPLICATION ─────────────────────────────────────────────────────────
def _dedup_urls(urls: Set[str]) -> List[str]:
    """
    Return unique parameterised URLs by (netloc, path, frozenset of param names).
    Prevents scanning the same endpoint multiple times with different param values.
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


# ── FORM → PARAMETERISED URL CONVERTER ───────────────────────────────────────
def _form_to_url(action: str, inputs: List[Dict], method: str, base_url: str) -> Optional[str]:
    """
    Convert a discovered HTML form into a parameterised URL for scanning.
    Fills each input with a safe test value so the URL has real parameters.
    GET forms → parameterised URL
    POST forms → parameterised URL with method noted (scanner handles POST separately)
    """
    if not action:
        action = base_url

    full_action = urljoin(base_url, action)

    # Build param dict with safe test values
    params: Dict[str, str] = {}
    for inp in inputs:
        name  = inp.get("name", "").strip()
        itype = inp.get("type", "text").lower()
        if not name:
            continue
        # Use type-appropriate safe test values
        if itype in ("email",):
            params[name] = "test@permi.dev"
        elif itype in ("number", "range"):
            params[name] = "1"
        elif itype in ("tel",):
            params[name] = "08012345678"
        elif itype in ("url",):
            params[name] = "https://permi.dev"
        elif itype in ("password",):
            params[name] = "TestPass123"
        elif itype in ("hidden",):
            params[name] = inp.get("value", "1")
        elif itype in ("checkbox", "radio"):
            params[name] = inp.get("value", "on")
        else:
            params[name] = "permi_test"

    if not params:
        return None

    query = urlencode(params)
    return f"{full_action}?{query}"


# ── MAIN JS CRAWLER ───────────────────────────────────────────────────────────
class JSCrawler:
    """
    Playwright-based crawler that executes JavaScript and extracts:
    - All anchor links (including JS-rendered ones)
    - All forms with their input fields
    - All XHR/fetch API endpoint calls made by the page
    - Search inputs and filter components
    """

    def __init__(
        self,
        base_url:           str,
        max_pages:          int  = 20,
        include_subdomains: bool = False,
        timeout_ms:         int  = 15000,
    ):
        self.base_url           = base_url
        self.max_pages          = max_pages
        self.include_subdomains = include_subdomains
        self.timeout_ms         = timeout_ms

        parsed           = urlparse(base_url)
        netloc           = parsed.netloc.split(":")[0].lower()
        self.base_domain = _extract_base_domain(netloc)

    async def crawl(self) -> Tuple[List[str], List[str], bool]:
        """
        Crawl the target using a headless Chromium browser.

        Returns:
            (parameterised_urls, api_endpoints, is_spa)
            parameterised_urls — unique URLs with query params for scanning
            api_endpoints      — XHR/fetch endpoints discovered via network interception
            is_spa             — always True when JS crawler is used
        """
        from playwright.async_api import async_playwright, TimeoutError as PWTimeout

        discovered_urls:  Set[str]  = set()
        api_endpoints:    List[str] = []
        visited:          Set[str]  = set()
        pages_crawled:    int       = 0

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",   # important for low-RAM systems
                    "--disable-gpu",
                    "--disable-extensions",
                    "--memory-pressure-off",
                ]
            )

            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )

            # Intercept network requests to discover API endpoints
            api_seen: Set[str] = set()

            async def handle_request(request):
                """Capture XHR/fetch calls to discover API endpoints."""
                if request.resource_type in ("xhr", "fetch"):
                    req_url = request.url
                    parsed  = urlparse(req_url)
                    # Only capture in-scope API calls
                    if _in_scope(req_url, self.base_domain, self.include_subdomains):
                        if parsed.path not in api_seen:
                            api_seen.add(parsed.path)
                            # Build a parameterised URL if query params exist
                            if parsed.query:
                                api_endpoints.append(req_url)

            # Queue starts with the base URL
            to_visit = [self.base_url]

            while to_visit and pages_crawled < self.max_pages:
                current_url = to_visit.pop(0)
                if current_url in visited:
                    continue
                visited.add(current_url)
                pages_crawled += 1

                page = await context.new_page()
                page.on("request", handle_request)

                try:
                    print(
                        f"[Permi JS] Rendering page {pages_crawled}/{self.max_pages}: "
                        f"{current_url[:70]}{'...' if len(current_url) > 70 else ''}"
                    )

                    # Navigate and wait for network to settle
                    await page.goto(
                        current_url,
                        wait_until="networkidle",
                        timeout=self.timeout_ms,
                    )

                    # Extra wait for slow React/Vue renders
                    await asyncio.sleep(1.5)

                    # ── Extract links from the live DOM ───────────────────────
                    links = await page.evaluate("""
                        () => {
                            const seen = new Set();
                            const results = [];
                            document.querySelectorAll('a[href]').forEach(a => {
                                const href = a.href;
                                if (href && !seen.has(href)) {
                                    seen.add(href);
                                    results.push(href);
                                }
                            });
                            return results;
                        }
                    """)

                    for link in links:
                        try:
                            full = urljoin(current_url, link)
                            # Strip fragments
                            full = full.split("#")[0]
                            if (
                                _in_scope(full, self.base_domain, self.include_subdomains)
                                and full not in visited
                                and full not in discovered_urls
                            ):
                                discovered_urls.add(full)
                                to_visit.append(full)
                        except Exception:
                            continue

                    # ── Extract forms from the live DOM ───────────────────────
                    forms = await page.evaluate("""
                        () => {
                            const results = [];
                            document.querySelectorAll('form').forEach(form => {
                                const inputs = [];
                                form.querySelectorAll('input, textarea, select').forEach(inp => {
                                    if (inp.name) {
                                        inputs.push({
                                            name:  inp.name,
                                            type:  inp.type || 'text',
                                            value: inp.value || ''
                                        });
                                    }
                                });
                                results.push({
                                    action: form.action || '',
                                    method: form.method || 'get',
                                    inputs: inputs
                                });
                            });
                            return results;
                        }
                    """)

                    for form in forms:
                        form_url = _form_to_url(
                            action   = form.get("action", ""),
                            inputs   = form.get("inputs", []),
                            method   = form.get("method", "get"),
                            base_url = current_url,
                        )
                        if form_url:
                            discovered_urls.add(form_url)

                    # ── Try to trigger search boxes ───────────────────────────
                    # Many SPAs only show parameterised URLs after user interaction
                    try:
                        search_inputs = await page.query_selector_all(
                            "input[type='search'], input[placeholder*='search' i], "
                            "input[placeholder*='query' i], input[name='q'], "
                            "input[name='search'], input[name='keyword']"
                        )
                        for inp in search_inputs[:2]:  # max 2 search boxes per page
                            try:
                                await inp.fill("test")
                                await inp.press("Enter")
                                await asyncio.sleep(1.0)
                                # Capture the resulting URL with search params
                                search_url = page.url
                                if "?" in search_url:
                                    discovered_urls.add(search_url)
                                await page.go_back(timeout=5000)
                                await asyncio.sleep(0.5)
                            except Exception:
                                continue
                    except Exception:
                        pass

                except PWTimeout:
                    print(f"[Permi JS] Page timeout: {current_url[:60]} — skipping")
                except Exception as e:
                    print(f"[Permi JS] Error on {current_url[:60]}: {type(e).__name__} — skipping")
                finally:
                    try:
                        await page.close()
                    except Exception:
                        pass

            await browser.close()

        # Add API endpoints discovered via network interception
        for ep in api_endpoints:
            discovered_urls.add(ep)

        # Deduplicate before returning
        unique = _dedup_urls(discovered_urls)

        print(
            f"[Permi JS] Crawl complete — {pages_crawled} pages rendered, "
            f"{len(discovered_urls)} URLs found, "
            f"{len(unique)} unique parameter signatures to test"
        )
        if api_endpoints:
            print(f"[Permi JS] {len(api_endpoints)} API endpoint(s) discovered via network interception")

        return unique, api_endpoints, True


# ── SYNCHRONOUS ENTRY POINT ───────────────────────────────────────────────────
def crawl_js(
    url:                str,
    max_pages:          int  = 20,
    include_subdomains: bool = False,
) -> Tuple[List[str], List[str], bool]:
    """
    Synchronous wrapper for JSCrawler.crawl().
    Called by web_scanner._run_web_scan() when --js flag is set.
    Returns: (parameterised_urls, api_endpoints, is_spa)
    """
    crawler = JSCrawler(
        base_url           = url,
        max_pages          = max_pages,
        include_subdomains = include_subdomains,
    )
    return asyncio.run(crawler.crawl())


# ── INSTALL HELPER ────────────────────────────────────────────────────────────
def print_install_guide():
    """Print clear installation instructions when Playwright is missing."""
    from colorama import Fore, Style
    print(f"""
{Fore.YELLOW}[Permi] Playwright is not installed.{Style.RESET_ALL}
{Fore.YELLOW}[Permi] The --js flag requires Playwright to render JavaScript.{Style.RESET_ALL}

{Fore.WHITE}  Install with:{Style.RESET_ALL}
    pip install playwright
    playwright install chromium

{Fore.WHITE}  Then retry:{Style.RESET_ALL}
    permi scan --url {"{your-target}"} --js

{Fore.CYAN}[Permi] Note: Chromium download is ~130MB (one-time).{Style.RESET_ALL}
{Fore.CYAN}[Permi] On a 4GB RAM machine, use --max-pages 10 with --js{Style.RESET_ALL}
{Fore.CYAN}[Permi]   to keep memory usage manageable.{Style.RESET_ALL}
""")
