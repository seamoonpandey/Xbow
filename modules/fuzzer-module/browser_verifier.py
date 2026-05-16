"""
browser_verifier — confirms xss execution using playwright headless browser
navigates to injected url and detects javascript alert/confirm/prompt dialogs
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

logger = logging.getLogger(__name__)

# try to import playwright, gracefully degrade if unavailable
try:
    from playwright.async_api import async_playwright, Dialog, Page, Error as PWError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("playwright not available, browser verification disabled")


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
FRAGMENT_PARAM = "__fragment__"


@dataclass
class VerifyResult:
    """result of browser-based execution verification"""
    payload: str
    target_param: str
    executed: bool
    dialog_triggered: bool
    dialog_message: str
    console_errors: list[str] = field(default_factory=list)
    dom_mutations: int = 0
    elapsed_ms: float = 0
    error: str | None = None


async def verify_payloads(
    url: str,
    reflected_results: list[dict],
    timeout_ms: int = 10000,
    concurrency: int = 3,
) -> list[VerifyResult]:
    """
    verify reflected payloads using headless chromium.
    only tests payloads that were confirmed reflected in the response.
    """
    if not PLAYWRIGHT_AVAILABLE:
        logger.warning("playwright unavailable, skipping browser verification")
        return [
            VerifyResult(
                payload=r["payload"],
                target_param=r["target_param"],
                executed=False,
                dialog_triggered=False,
                dialog_message="",
                error="playwright not installed",
            )
            for r in reflected_results
        ]

    results: list[VerifyResult] = []
    semaphore = asyncio.Semaphore(concurrency)

    try:
        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-extensions",
                    ],
                )
            except Exception as e:
                logger.warning(f"playwright launch failed: {e}")
                return [
                    VerifyResult(
                        payload=r.get("payload", ""),
                        target_param=r.get("target_param", ""),
                        executed=False,
                        dialog_triggered=False,
                        dialog_message="",
                        error=f"playwright launch failed: {e}",
                    )
                    for r in reflected_results
                ]

            try:
                tasks = [
                    _verify_one(browser, semaphore, url, entry, timeout_ms)
                    for entry in reflected_results
                ]
                raw = await asyncio.gather(*tasks, return_exceptions=True)

                for r in raw:
                    if isinstance(r, VerifyResult):
                        results.append(r)
                    elif isinstance(r, Exception):
                        logger.warning(f"verify error: {r}")
            finally:
                await browser.close()
    except Exception as e:
        logger.warning(f"playwright init failed: {e}")
        return [
            VerifyResult(
                payload=r.get("payload", ""),
                target_param=r.get("target_param", ""),
                executed=False,
                dialog_triggered=False,
                dialog_message="",
                error=f"playwright init failed: {e}",
            )
            for r in reflected_results
        ]

    executed_count = sum(1 for r in results if r.executed)
    logger.info(f"browser verify: {executed_count}/{len(results)} executed")
    return results


async def _verify_one(
    browser,
    semaphore: asyncio.Semaphore,
    base_url: str,
    entry: dict,
    timeout_ms: int,
) -> VerifyResult:
    """verify a single payload in a fresh browser context"""
    async with semaphore:
        payload = entry.get("payload", "")
        param = entry.get("target_param", "")
        start = time.monotonic()

        context = await browser.new_context(
            ignore_https_errors=True,
            java_script_enabled=True,
            user_agent=DEFAULT_USER_AGENT,
            extra_http_headers=DEFAULT_HEADERS,
        )

        page = await context.new_page()
        dialog_info: dict = {"triggered": False, "message": ""}
        console_errors: list[str] = []
        nav_error: str | None = None
        execution_flags: dict = {
            "alert_called": False,
            "script_executed": False,
            "injection_detected": False
        }

        try:
            # listen for dialogs (alert, confirm, prompt)
            async def handle_dialog(dialog: Dialog):
                dialog_info["triggered"] = True
                dialog_info["message"] = dialog.message
                # also mark the execution flag so returned result is consistent
                try:
                    execution_flags["alert_called"] = True
                except Exception:
                    pass
                await dialog.dismiss()

            page.on("dialog", handle_dialog)

            # capture console messages and look for our alert marker
            def _on_console(msg):
                try:
                    text = msg.text
                except Exception:
                    return
                if msg.type == "error":
                    console_errors.append(text)
                if text and text.startswith("[xss-verifier-alert]"):
                    try:
                        execution_flags["alert_called"] = True
                        dialog_info["triggered"] = True
                        dialog_info["message"] = text.replace("[xss-verifier-alert]", "")
                    except Exception:
                        pass

            page.on("console", _on_console)

            # inject execution tracking before payload
            try:
                await page.add_init_script("""
                    // XSS verifier helper object
                    window._xss_verification = {
                        alert_called: false,
                        script_executed: false,
                        last_alert: null
                    };
                    // override alert to reliably mark execution and emit a console marker
                    window.alert = function(msg) {
                        try { window._xss_verification.alert_called = true; } catch(e){}
                        try { window._xss_verification.last_alert = String(msg); } catch(e){}
                        try { console.log('[xss-verifier-alert]'+String(msg)); } catch(e){}
                        // do not call original alert to avoid blocking in headless
                    };
                    window._xss_verification.script_executed = true;
                """)
            except Exception as e:
                logger.debug(f"init script injection failed: {e}")
            # build the injected url
            injected_url = _inject_param(base_url, param, payload)

            # navigate (networkidle is brittle on modern pages; DOMContentLoaded is safer)
            try:
                await page.goto(
                    injected_url,
                    wait_until="domcontentloaded",
                    timeout=timeout_ms,
                )
            except Exception as e:
                # even on timeout/nav error, dialog may have fired
                nav_error = f"goto failed: {e}"

            # optionally wait for network to settle (best-effort, 1.5 s cap so it
            # never blocks the whole batch waiting for analytics/websockets)
            try:
                await page.wait_for_load_state("networkidle", timeout=1500)
            except Exception:
                pass  # non-fatal — DOMContentLoaded is enough for XSS detection

            # trigger window.onload handlers by dispatching a synthetic load
            # event.  Waiting for the real load event is too slow (up to 5 s
            # per payload for images/analytics) and causes the fuzzer to hit
            # its HTTP timeout.  Dispatching the event directly is ~200 ms and
            # achieves the same result — many apps (e.g. XSS Game Level 3)
            # create vulnerable DOM content in window.onload using jQuery
            # .html() which we need to exist before we force-dispatch events.
            try:
                await page.evaluate("() => window.dispatchEvent(new Event('load'))")
                await page.wait_for_timeout(200)
            except Exception:
                pass

            # actively trigger user-driven vectors (onclick/onfocus/javascript: links)
            # so click-dependent payloads can be confirmed.
            await _attempt_user_interactions(page, payload, param)

            # brief wait for any delayed js execution (force-dispatched events
            # in _attempt_user_interactions are synchronous inside the JS
            # evaluate context, so a short wait is sufficient)
            await page.wait_for_timeout(800)

            # check execution flags
            try:
                exec_flags = await page.evaluate("window._xss_verification || {}")
                execution_flags.update(exec_flags)
            except Exception:
                pass
            # check for dom mutations that indicate script injection
            dom_mutations = await _count_injected_elements(page, payload)

            elapsed = (time.monotonic() - start) * 1000
            # execution confirmed if:
            # 1. Dialog popped up (strongest signal)
            # 2. Alert function was actually called (bypass detection)
            # 3. Injected elements exist AND payload suggests execution
            executed = (
                dialog_info["triggered"] or 
                execution_flags.get("alert_called", False) or
                (dom_mutations > 0 and _payload_suggests_execution(payload))
            )

            return VerifyResult(
                payload=payload,
                target_param=param,
                executed=executed,
                dialog_triggered=dialog_info["triggered"],
                dialog_message=dialog_info["message"],
                console_errors=console_errors,
                dom_mutations=dom_mutations,
                elapsed_ms=round(elapsed, 2),
                error=nav_error,
            )

        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return VerifyResult(
                payload=payload,
                target_param=param,
                executed=False,
                dialog_triggered=dialog_info["triggered"],
                dialog_message=dialog_info["message"],
                console_errors=console_errors,
                elapsed_ms=round(elapsed, 2),
                error=str(e),
            )
        finally:
            await context.close()


async def _count_injected_elements(page, payload: str) -> int:
    """check if payload created new dom elements (img, svg, iframe, etc.)"""
    try:
        # look for elements likely created by xss payloads
        count = await page.evaluate("""() => {
            const suspicious = document.querySelectorAll(
                'img[onerror], svg[onload], iframe[src*="javascript:"], '
                + 'body[onload], input[onfocus], details[ontoggle], '
                + 'video[onerror], audio[onerror], math[onload]'
            );
            return suspicious.length;
        }""")
        return count
    except Exception:
        return 0


async def _attempt_user_interactions(page, payload: str, param: str) -> None:
    """best-effort simulation of basic user actions to trigger event-based payloads."""
    try:
        payload_lower = payload.lower()

        # Click javascript: links when present (Level 5 style).
        # We click them regardless of payload content because the reflection 
        # might just be the payload part of href="javascript:PAYLOAD"
        try:
            await page.evaluate("""() => {
                const anchors = Array.from(document.querySelectorAll('a[href]'));
                for (const a of anchors) {
                    const href = (a.getAttribute('href') || '').toLowerCase();
                    if (href.startsWith('javascript:')) {
                        a.click();
                    }
                }
            }""")
        except Exception:
            pass

        # Click elements likely to contain inline click handlers.
        if any(x in payload_lower for x in ["onclick", "onmousedown", "onmouseup"]):
            try:
                await page.evaluate("""() => {
                    const clickable = document.querySelectorAll('[onclick], [onmousedown], [onmouseup], button, a, input[type="button"], input[type="submit"]');
                    for (const el of clickable) {
                        if (typeof el.click === 'function') el.click();
                    }
                }""")
            except Exception:
                pass

        # Focus/blur events often need explicit focus to execute.
        if any(x in payload_lower for x in ["onfocus", "onblur", "onfocusin", "onfocusout"]):
            try:
                await page.evaluate("""() => {
                    const focusables = document.querySelectorAll('[onfocus], [onblur], [onfocusin], [onfocusout], input, textarea, select, button, a[href], [tabindex]');
                    for (const el of focusables) {
                        if (typeof el.focus === 'function') {
                            el.focus();
                            if (typeof el.blur === 'function') el.blur();
                        }
                    }
                }""")
            except Exception:
                pass

        # Hover and keyboard-driven handlers.
        if any(x in payload_lower for x in ["onmouseover", "onmouseenter", "onkeydown", "onkeyup", "onkeypress"]):
            try:
                await page.evaluate("""() => {
                    const candidates = document.querySelectorAll('[onmouseover], [onmouseenter], [onkeydown], [onkeyup], [onkeypress], *');
                    for (const el of candidates) {
                        el.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
                        el.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));
                        el.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'Enter' }));
                        el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'Enter' }));
                    }
                }""")
            except Exception:
                pass

        # Generic fallback: try Enter key once to trigger default actions.
        try:
            await page.keyboard.press("Enter")
        except Exception:
            pass

        # Give handlers a short window to execute.
        await page.wait_for_timeout(400)
        # Force-dispatch load/error events on elements that have inline handlers
        try:
            await page.evaluate("""() => {
                const imgs = Array.from(document.querySelectorAll('img[onerror]'));
                for (const img of imgs) {
                    try {
                        try { img.src = 'about:invalid#xss'; } catch(e){}
                        img.dispatchEvent(new Event('error', { bubbles: true }));
                    } catch(e){}
                }
                const svgs = Array.from(document.querySelectorAll('svg[onload]'));
                for (const s of svgs) {
                    try { s.dispatchEvent(new Event('load', { bubbles: true })); } catch(e){}
                }
                const others = Array.from(document.querySelectorAll('[onload],[onerror]'));
                for (const el of others) {
                    try {
                        if (el.hasAttribute('onerror')) el.dispatchEvent(new Event('error', { bubbles: true }));
                        if (el.hasAttribute('onload')) el.dispatchEvent(new Event('load', { bubbles: true }));
                    } catch(e){}
                }
            }""")
        except Exception:
            pass
    except Exception:
        # best-effort helper: verification should not fail due to interaction attempts
        return

def _payload_suggests_execution(payload: str) -> bool:
    """
    check if the payload structure suggests it should have executed.
    this distinguishes between "element exists" and "code executed"
    """
    payload_lower = payload.lower()
    
    # payloads with indicators that suggest execution without user interaction
    executing_indicators = [
        'alert(',      # direct function call
        'prompt(',     # direct function call
        'confirm(',    # direct function call
        'console.log(', # safe execution marker
        'eval(',       # definitely executes
        'onerror',     # img/audio/video onerror handlers
        'onload',      # svg/body onload handlers
    ]
    
    for indicator in executing_indicators:
        if indicator in payload_lower:
            return True
    
    # payloads that might not execute (event handlers that require user action)
    non_executing_patterns = [
        'onclick',     # requires user click
        'onmouseover', # requires mouse over
        'onkeydown',   # requires key press
        'onfocus',     # requires focus (not automatic)
    ]
    
    for pattern in non_executing_patterns:
        if pattern in payload_lower:
            return False
    
    # default: assume safe indicators like onerror/onload are reliable
    return True

async def verify_stored_form_payloads(
    page_url: str,
    payload_entries: list[dict],
    form_fields: dict,
    timeout_ms: int = 10000,
    concurrency: int = 3,
) -> list[VerifyResult]:
    """
    verify stored/dom-based xss by submitting form payloads via headless browser.
    handles client-side storage (localStorage, cookies) that raw http cannot reach.
    for each payload: navigate → clear storage → fill form → submit → detect dialog.
    """
    if not PLAYWRIGHT_AVAILABLE:
        logger.warning("playwright unavailable, skipping stored form browser verification")
        return [
            VerifyResult(
                payload=e.get("payload", ""),
                target_param=e.get("target_param", ""),
                executed=False,
                dialog_triggered=False,
                dialog_message="",
                error="playwright not installed",
            )
            for e in payload_entries
        ]

    results: list[VerifyResult] = []
    semaphore = asyncio.Semaphore(concurrency)

    try:
        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-extensions",
                    ],
                )
            except Exception as e:
                logger.warning(f"playwright launch failed (stored form): {e}")
                return [
                    VerifyResult(
                        payload=e2.get("payload", ""),
                        target_param=e2.get("target_param", ""),
                        executed=False,
                        dialog_triggered=False,
                        dialog_message="",
                        error=f"playwright launch failed: {e}",
                    )
                    for e2 in payload_entries
                ]

            try:
                tasks = [
                    _verify_stored_one(browser, semaphore, page_url, entry, form_fields, timeout_ms)
                    for entry in payload_entries
                ]
                raw = await asyncio.gather(*tasks, return_exceptions=True)

                for r in raw:
                    if isinstance(r, VerifyResult):
                        results.append(r)
                    elif isinstance(r, Exception):
                        logger.warning(f"stored form verify error: {r}")
            finally:
                await browser.close()
    except Exception as e:
        logger.warning(f"playwright init failed (stored form): {e}")
        return [
            VerifyResult(
                payload=e2.get("payload", ""),
                target_param=e2.get("target_param", ""),
                executed=False,
                dialog_triggered=False,
                dialog_message="",
                error=f"playwright init failed: {e}",
            )
            for e2 in payload_entries
        ]

    executed_count = sum(1 for r in results if r.executed)
    logger.info(f"stored form verify: {executed_count}/{len(results)} executed")
    return results


async def _verify_stored_one(
    browser,
    semaphore: asyncio.Semaphore,
    page_url: str,
    entry: dict,
    form_fields: dict,
    timeout_ms: int,
) -> VerifyResult:
    """verify a single stored/dom payload by submitting a form in a fresh browser context"""
    async with semaphore:
        payload = entry.get("payload", "")
        param = entry.get("target_param", "")
        start = time.monotonic()

        context = await browser.new_context(
            ignore_https_errors=True,
            java_script_enabled=True,
            user_agent=DEFAULT_USER_AGENT,
            extra_http_headers=DEFAULT_HEADERS,
        )

        page = await context.new_page()
        dialog_info: dict = {"triggered": False, "message": ""}
        nav_error: str | None = None

        try:
            async def handle_dialog(dialog: Dialog):
                dialog_info["triggered"] = True
                dialog_info["message"] = dialog.message
                await dialog.dismiss()

            page.on("dialog", handle_dialog)

            # navigate to the page containing the form
            try:
                await page.goto(
                    page_url,
                    wait_until="load",
                    timeout=timeout_ms,
                )
            except Exception as e:
                nav_error = f"goto failed: {e}"

            # NOTE: do NOT clear localStorage — PostDB (and similar client-side
            # stores) initialise themselves on page load from existing localStorage.
            # Clearing it after load corrupts the DB object already in memory and
            # causes JSON.parse(null) errors when save() is called.
            # Each verify gets its own fresh Playwright context (new_context()),
            # so localStorage is already isolated and empty at navigate time.

            # fill non-target fields with their default values
            for field_name, field_value in (form_fields or {}).items():
                if field_name == param:
                    continue
                try:
                    await page.fill(f'[name="{field_name}"]', str(field_value), timeout=1000)
                except Exception:
                    pass  # field may not be present or editable

            # fill the target field with the xss payload
            try:
                await page.fill(f'[name="{param}"]', payload, timeout=2000)
            except Exception as fill_err:
                nav_error = f"fill failed: {fill_err}"

            # submit the form: find the form containing the target field
            # and click its submit button (triggers JS onsubmit handlers)
            try:
                submitted = await page.evaluate(f"""() => {{
                    const el = document.querySelector('[name="{param}"]');
                    if (!el) return false;
                    const form = el.closest('form');
                    if (!form) return false;
                    const btn = form.querySelector('[type="submit"], button');
                    if (btn) {{ btn.click(); return true; }}
                    form.submit();
                    return true;
                }}""")
                if not submitted:
                    # fallback: press Enter on the field
                    await page.keyboard.press("Enter")
            except Exception as submit_err:
                nav_error = f"submit failed: {submit_err}"

            # wait for dialog to fire from immediate DOM re-render (e.g. innerHTML sink)
            await page.wait_for_timeout(1200)

            # also check for injected elements in the DOM
            dom_mutations = await _count_injected_elements(page, payload)
            elapsed = (time.monotonic() - start) * 1000
            executed = dialog_info["triggered"] or dom_mutations > 0

            return VerifyResult(
                payload=payload,
                target_param=param,
                executed=executed,
                dialog_triggered=dialog_info["triggered"],
                dialog_message=dialog_info["message"],
                dom_mutations=dom_mutations,
                elapsed_ms=round(elapsed, 2),
                error=nav_error,
            )

        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return VerifyResult(
                payload=payload,
                target_param=param,
                executed=False,
                dialog_triggered=dialog_info["triggered"],
                dialog_message=dialog_info["message"],
                elapsed_ms=round(elapsed, 2),
                error=str(e),
            )
        finally:
            await context.close()


def _inject_param(url: str, param: str, value: str) -> str:
    """inject payload into url query parameter"""
    parsed = urlparse(url)
    if param == FRAGMENT_PARAM:
        return urlunparse(parsed._replace(fragment=value))

    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
