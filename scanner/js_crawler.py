# scanner/js_crawler.py  — v0.3
#


from __future__ import annotations

import asyncio
import concurrent.futures
import time
from typing import Set, List, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin, urlencode, parse_qs


def stealth_available() -> bool:
    try:
        from playwright_stealth import Stealth  # noqa: F401
        return True
    except ImportError:
        return False


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _extract_base_domain(netloc: str) -> str:
    host  = netloc.split(":")[0].lower()
    parts = host.split(".")
    tlds  = {"edu.ng","co.uk","com.ng","org.ng","gov.ng","net.ng","com.au","co.za","ac.uk","org.uk","co.nz","com.br","co.in"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in tlds:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _in_scope(url: str, base_domain: str, include_subdomains: bool) -> bool:
    try:
        netloc = urlparse(url).netloc.split(":")[0].lower()
        if not netloc:
            return False
        return (_extract_base_domain(netloc) == base_domain) if include_subdomains else (netloc == base_domain)
    except Exception:
        return False


def _dedup_urls(urls: Set[str]) -> List[str]:
    seen, unique = set(), []
    for url in urls:
        if "?" not in url:
            continue
        p   = urlparse(url)
        sig = (p.netloc, p.path, frozenset(parse_qs(p.query).keys()))
        if sig not in seen:
            seen.add(sig)
            unique.append(url)
    return unique


def _form_to_url(action: str, inputs: List[Dict], base_url: str) -> Optional[str]:
    if not action:
        action = base_url
    full_action = urljoin(base_url, action)
    params: Dict[str, str] = {}
    for inp in inputs:
        name  = inp.get("name", "").strip()
        itype = inp.get("type", "text").lower()
        if not name:
            continue
        if itype == "email":               params[name] = "test@permi.dev"
        elif itype in ("number","range"):  params[name] = "1"
        elif itype == "tel":               params[name] = "08012345678"
        elif itype == "url":               params[name] = "https://permi.dev"
        elif itype == "hidden":            params[name] = inp.get("value","1")
        elif itype in ("checkbox","radio"):params[name] = inp.get("value","on")
        elif itype == "password":          params[name] = "TestPass123"
        else:                              params[name] = "permi_test"
    if not params:
        return None
    return f"{full_action}?{urlencode(params)}"


# ── CHANGE 2: STATIC FALLBACK ─────────────────────────────────────────────────
def _static_fallback(
    url:               str,
    base_domain:       str,
    include_subdomains: bool,
) -> Tuple[Set[str], List[Dict]]:
    """
    CHANGE 2 — called inside except PWTimeout.
    Fetches the page with plain httpx and extracts links + forms
    using BeautifulSoup. No JavaScript, but gets something instead of nothing.
    """
    try:
        import httpx
        from bs4 import BeautifulSoup

        resp = httpx.get(
            url,
            headers       = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            },
            follow_redirects = True,
            timeout          = 10,
            verify           = False,
        )
        soup  = BeautifulSoup(resp.text, "html.parser")
        urls: Set[str]    = set()
        forms: List[Dict] = []

        for tag in soup.find_all("a", href=True):
            full = urljoin(url, tag["href"]).split("#")[0]
            if _in_scope(full, base_domain, include_subdomains):
                urls.add(full)

        for form in soup.find_all("form"):
            inputs = []
            for inp in form.find_all(["input","textarea","select"]):
                name  = inp.get("name","")
                itype = inp.get("type","text")
                if name and itype not in ("submit","button","image","reset"):
                    inputs.append({
                        "name":  name,
                        "type":  itype,
                        "value": inp.get("value",""),
                    })
            if inputs:
                forms.append({
                    "action": form.get("action",""),
                    "method": form.get("method","get").lower(),
                    "inputs": inputs,
                })

        print(
            f"[Permi JS] Static fallback OK: "
            f"{len(urls)} link(s), {len(forms)} form(s) — {url[:50]}"
        )
        return urls, forms

    except Exception as e:
        print(f"[Permi JS] Static fallback failed ({type(e).__name__}) — {url[:50]}")
        return set(), []


# ── CORE ASYNC CRAWL (always runs in its own thread — Windows deadlock fix) ───
async def _async_crawl(
    base_url:           str,
    max_pages:          int,
    include_subdomains: bool,
    page_timeout_ms:    int,
    stop_flag,                  # threading.Event — set when main thread moves on
) -> Tuple[List[str], List[str]]:
    """
    Core Playwright crawl. Runs inside its own thread (Windows deadlock fix).
    Uses stop_flag to silence output once main thread has finished waiting.
    This prevents JS crawler messages from appearing after the scan summary,
    AI filter output, feedback prompt, and export message.
    """
    from playwright.async_api import async_playwright, TimeoutError as PWTimeout

    def _p(msg: str):
        """Print only if main thread is still waiting for us."""
        if not stop_flag.is_set():
            print(msg)

    try:
        from playwright_stealth import Stealth
        _stealth     = Stealth()
        _has_stealth = True
    except ImportError:
        _stealth     = None
        _has_stealth = False

    netloc      = urlparse(base_url).netloc.split(":")[0].lower()
    base_domain = _extract_base_domain(netloc)

    discovered_urls: Set[str]  = set()
    api_endpoints:   List[str] = []
    api_seen:        Set[str]  = set()
    visited:         Set[str]  = set()
    to_visit:        List[str] = [base_url]
    pages_crawled:   int       = 0
    js_timeouts:     int       = 0

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless = True,
            args     = [
                "--no-sandbox", "--disable-setuid-sandbox",
                "--disable-dev-shm-usage", "--disable-gpu",
                "--disable-extensions", "--disable-background-networking",
                "--disable-default-apps", "--memory-pressure-off",
                "--single-process",
            ],
        )

        context = await browser.new_context(
            viewport            = {"width": 1280, "height": 800},
            user_agent          = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            ignore_https_errors = True,
            extra_http_headers  = {
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "DNT": "1",
            },
        )

        while to_visit and pages_crawled < max_pages:
            # Stop crawling immediately if main thread moved on
            if stop_flag.is_set():
                break

            current_url = to_visit.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)
            pages_crawled += 1

            _p(
                f"[Permi JS] Rendering {pages_crawled}/{max_pages}: "
                f"{current_url[:70]}{'...' if len(current_url) > 70 else ''}"
            )

            page = await context.new_page()

            if _has_stealth:
                await _stealth.apply_stealth_async(page)

            async def on_request(request):
                if request.resource_type in ("xhr", "fetch"):
                    req_url = request.url
                    p       = urlparse(req_url)
                    if _in_scope(req_url, base_domain, include_subdomains):
                        if p.path not in api_seen:
                            api_seen.add(p.path)
                            if p.query:
                                api_endpoints.append(req_url)
                                _p(f"[Permi JS] API endpoint: {req_url[:65]}")

            page.on("request", on_request)

            try:
                await page.goto(
                    current_url,
                    wait_until = "domcontentloaded",
                    timeout    = page_timeout_ms,
                )
                await asyncio.sleep(1.5)

                # Links
                try:
                    links = await page.evaluate("""() => {
                        const seen=new Set(),out=[];
                        document.querySelectorAll('a[href]').forEach(a=>{
                            const h=a.href;
                            if(h&&!h.startsWith('javascript:')&&!h.startsWith('mailto:')&&!h.startsWith('tel:')&&!seen.has(h)){
                                seen.add(h);out.push(h);
                            }
                        });
                        return out;
                    }""")
                    for link in links:
                        full = urljoin(current_url, link).split("#")[0]
                        if _in_scope(full, base_domain, include_subdomains) and full not in visited:
                            discovered_urls.add(full)
                            if full not in to_visit:
                                to_visit.append(full)
                except Exception:
                    pass

                # Forms
                try:
                    forms = await page.evaluate("""() => {
                        const out=[];
                        document.querySelectorAll('form').forEach(f=>{
                            const inputs=[];
                            f.querySelectorAll('input:not([type=submit]):not([type=button]),textarea,select').forEach(i=>{
                                if(i.name) inputs.push({name:i.name,type:i.type||'text',value:i.value||''});
                            });
                            if(inputs.length) out.push({action:f.action||'',method:(f.method||'get').toLowerCase(),inputs});
                        });
                        return out;
                    }""")
                    for form in forms:
                        form_url = _form_to_url(form.get("action",""), form.get("inputs",[]), current_url)
                        if form_url:
                            discovered_urls.add(form_url)
                            _p(f"[Permi JS] Form discovered: {form_url[:65]}")
                except Exception:
                    pass

                # Search boxes
                try:
                    search = await page.query_selector_all(
                        "input[type='search'],input[placeholder*='search' i],"
                        "input[name='q'],input[name='search']"
                    )
                    for inp in search[:1]:
                        try:
                            await inp.fill("test", timeout=3000)
                            await inp.press("Enter")
                            await asyncio.sleep(1.0)
                            su = page.url
                            if "?" in su and su not in discovered_urls:
                                discovered_urls.add(su)
                                _p(f"[Permi JS] Search URL: {su[:65]}")
                            await page.go_back(timeout=5000)
                            await asyncio.sleep(0.5)
                        except Exception:
                            continue
                except Exception:
                    pass

            except PWTimeout:
                js_timeouts += 1
                timeout_secs = page_timeout_ms // 1000
                _p(f"[Permi JS] JS timeout ({timeout_secs}s) — trying static fallback...")

                fallback_urls, fallback_forms = _static_fallback(
                    current_url, base_domain, include_subdomains
                )
                for fu in fallback_urls:
                    if fu not in visited:
                        discovered_urls.add(fu)
                        if fu not in to_visit:
                            to_visit.append(fu)
                for form in fallback_forms:
                    form_url = _form_to_url(form.get("action",""), form.get("inputs",[]), current_url)
                    if form_url:
                        discovered_urls.add(form_url)
                        _p(f"[Permi JS] Fallback form: {form_url[:65]}")

                if js_timeouts >= 2:
                    higher = timeout_secs + 15
                    _p(
                        f"[Permi JS] Multiple timeouts. Try:"
                        f" permi scan --url {base_url} --js --js-timeout {higher}"
                    )

            except Exception as e:
                _p(f"[Permi JS] {type(e).__name__}: {current_url[:55]} — skipping")
            finally:
                try:
                    await page.close()
                except Exception:
                    pass

        await browser.close()

    for ep in api_endpoints:
        discovered_urls.add(ep)

    unique = _dedup_urls(discovered_urls)

    # Only print the final Done summary if main thread is still listening
    if not stop_flag.is_set():
        print()
        print(
            f"[Permi JS] Done — {pages_crawled} page(s) | "
            f"{js_timeouts} JS timeout(s) with static fallback | "
            f"{len(unique)} unique parameter signature(s) to test"
        )
        if not _has_stealth:
            print("[Permi JS] Install playwright-stealth: pip install playwright-stealth")

    return unique, api_endpoints, discovered_urls


# ── JSCrawler ─────────────────────────────────────────────────────────────────
class JSCrawler:
    """
    Playwright SPA crawler.
    Runs Playwright in a separate daemon thread to avoid Windows asyncio deadlock.
    Uses stop_flag (threading.Event) to silence thread output once the main
    scan thread moves on — prevents interleaved output with AI filter and summary.
    """

    def __init__(
        self,
        base_url:           str,
        max_pages:          int  = 15,
        include_subdomains: bool = False,
        max_minutes:        int  = 5,
        page_timeout_ms:    int  = 20000,
    ):
        self.base_url           = base_url
        self.max_pages          = max_pages
        self.include_subdomains = include_subdomains
        self.max_minutes        = max_minutes
        self.page_timeout_ms    = page_timeout_ms
        self.pages_rendered     = 0

    async def crawl(self) -> Tuple[List[str], List[str], bool]:
        import threading

        base_url           = self.base_url
        max_pages          = self.max_pages
        include_subdomains = self.include_subdomains
        page_timeout_ms    = self.page_timeout_ms
        max_seconds        = self.max_minutes * 60

        # ── PRE-CHECK: confirm target is reachable before launching Chromium ──
        print(f"[Permi JS] Checking target reachability...")
        try:
            import httpx as _httpx
            _probe = _httpx.get(
                base_url,
                timeout          = 10,
                follow_redirects = True,
                verify           = False,
                headers          = {"User-Agent": "Mozilla/5.0"},
            )
            print(f"[Permi JS] Target reachable — HTTP {_probe.status_code}")
        except Exception as _e:
            print(f"[Permi JS] ⚠️  Target unreachable: {type(_e).__name__}")
            print(f"[Permi JS]    Cannot start JS scan — site may be offline.")
            print(f"[Permi JS]    Tip: try again in a few minutes, or scan without --js")
            print(f"[Permi JS]    Returning header findings only.")
            return [], [], set()
        # ──────────────────────────────────────────────────────────────────────

        # stop_flag: set() by crawl() when it stops waiting for the thread.
        # The thread checks this before every print() call so output stops
        # cleanly the moment the main scan moves to AI filter / summary.
        stop_flag = threading.Event()

        result_holder = [None]
        error_holder  = [None]

        def _run():
            """Runs in a fresh daemon thread with its own event loop."""
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result_holder[0] = loop.run_until_complete(
                    _async_crawl(
                        base_url           = base_url,
                        max_pages          = max_pages,
                        include_subdomains = include_subdomains,
                        page_timeout_ms    = page_timeout_ms,
                        stop_flag          = stop_flag,
                    )
                )
            except Exception as exc:
                error_holder[0] = exc
            finally:
                loop.close()

        stealth_note = (
            " + stealth active ✓"
            if stealth_available()
            else " (no stealth — pip install playwright-stealth for Cloudflare bypass)"
        )
        print(f"[Permi JS] Starting headless Chromium{stealth_note}")
        print(
            f"[Permi JS] Pages: {self.max_pages} max  |  "
            f"Per-page timeout: {self.page_timeout_ms // 1000}s  |  "
            f"Hard cap: {self.max_minutes} min"
        )
        print()

        # daemon=True: Python won't wait 300s for the thread on shutdown
        t = threading.Thread(target=_run, daemon=True)
        t.start()

        # FIX: use run_in_executor so t.join() does NOT block the asyncio event
        # loop. Calling t.join() directly inside an async def corrupts event loop
        # state, causing asyncio.run() in scan_url() to return a bool instead of
        # (findings, info) — producing "object of type 'bool' has no len()".
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: t.join(max_seconds))

        # Signal the thread to stop printing — whether it finished or timed out
        stop_flag.set()

        if t.is_alive():
            # Hard cap reached — thread still running but we move on
            print(f"\n[Permi JS] ⚠️  Hard cap reached ({self.max_minutes} min).")
            print(f"[Permi JS]    Continuing with header findings collected so far.")
            print(f"[Permi JS]    Try --max-pages 5 to scan faster next time.")
            return [], [], set()

        if error_holder[0]:
            print(f"\n[Permi JS] Browser error: {type(error_holder[0]).__name__}: {error_holder[0]}")
            print("[Permi JS]    Continuing with header findings only.")
            return [], [], set()

        if result_holder[0] is None:
            return [], [], set()

        unique, api_endpoints, all_discovered = result_holder[0]
        return unique, api_endpoints, all_discovered


# ── INSTALL GUIDES ────────────────────────────────────────────────────────────
def print_install_guide():
    from colorama import Fore, Style
    print(f"""
{Fore.YELLOW}[Permi] Playwright is not installed.{Style.RESET_ALL}

{Fore.WHITE}  Step 1 — Install Playwright:{Style.RESET_ALL}
    pip install playwright

{Fore.WHITE}  Step 2 — Download Chromium (~130MB, one-time):{Style.RESET_ALL}
    playwright install chromium

{Fore.WHITE}  Step 3 — Install stealth (bypasses Cloudflare):{Style.RESET_ALL}
    pip install playwright-stealth

{Fore.WHITE}  Step 4 — Re-run:{Style.RESET_ALL}
    permi scan --url {{target}} --js

{Fore.CYAN}  Tips:{Style.RESET_ALL}
    4GB RAM machine   → use --max-pages 10
    Cloudflare site   → use --js-timeout 45
    Heroku (sleeping) → use --js-timeout 30
""")


def print_stealth_install_hint():
    from colorama import Fore, Style
    print(
        f"{Fore.YELLOW}[Permi JS] playwright-stealth not installed.{Style.RESET_ALL}\n"
        f"{Fore.YELLOW}[Permi JS] Sites with Cloudflare or bot protection may timeout.{Style.RESET_ALL}\n"
        f"{Fore.YELLOW}[Permi JS] Fix: pip install playwright-stealth{Style.RESET_ALL}\n"
    )
