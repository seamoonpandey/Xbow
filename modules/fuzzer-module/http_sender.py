"""
http_sender — sends http requests with injected xss payloads
supports get and post injection into target parameters
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

logger = logging.getLogger(__name__)

# default headers to mimic a real browser
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

# methods to try when injecting
INJECT_METHODS = ["GET", "POST"]


@dataclass
class SendResult:
    """result of sending a single payload"""
    payload: str
    target_param: str
    method: str
    status_code: int
    response_body: str
    response_headers: dict[str, str]
    elapsed_ms: float
    error: str | None = None
    url: str = ""


@dataclass
class SendBatch:
    """batch of send results for one url"""
    results: list[SendResult] = field(default_factory=list)
    total_sent: int = 0
    total_errors: int = 0


async def send_payloads(
    url: str,
    payloads: list[dict],
    timeout_ms: int = 10000,
    concurrency: int = 10,
    methods: list[str] | None = None,
) -> SendBatch:
    """
    send all payloads against the target url.
    injects each payload into its target_param via get and post.
    returns batch of results with response bodies for reflection checking.
    """
    methods = methods or ["GET", "POST"]
    batch = SendBatch()
    semaphore = asyncio.Semaphore(concurrency)
    timeout_s = timeout_ms / 1000

    async with httpx.AsyncClient(
        headers=DEFAULT_HEADERS,
        timeout=httpx.Timeout(timeout_s, connect=5.0),
        follow_redirects=True,
        verify=False,
    ) as client:
        tasks = []
        for entry in payloads:
            payload_text = entry.get("payload", "")
            param = entry.get("target_param", "")
            for method in methods:
                tasks.append(
                    _send_one(client, semaphore, url, payload_text, param, method)
                )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, SendResult):
                batch.results.append(r)
                batch.total_sent += 1
                if r.error:
                    batch.total_errors += 1
            elif isinstance(r, Exception):
                batch.total_errors += 1
                logger.warning(f"send error: {r}")

    logger.info(
        f"sent {batch.total_sent} requests, {batch.total_errors} errors"
    )
    return batch


async def fetch_url(
    url: str,
    timeout_ms: int = 10000,
) -> SendResult:
    """Fetch a URL once (no injection).

    Used for DOM-only scanning on pages that have no injectable parameters.
    """
    timeout_s = timeout_ms / 1000
    start = time.monotonic()

    async with httpx.AsyncClient(
        headers=DEFAULT_HEADERS,
        timeout=httpx.Timeout(timeout_s, connect=5.0),
        follow_redirects=True,
        verify=False,
    ) as client:
        try:
            resp = await client.get(url)
            elapsed = (time.monotonic() - start) * 1000
            return SendResult(
                payload="",
                target_param="",
                method="GET",
                status_code=resp.status_code,
                response_body=resp.text,
                response_headers=dict(resp.headers),
                elapsed_ms=round(elapsed, 2),
                url=url,
            )
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return SendResult(
                payload="",
                target_param="",
                method="GET",
                status_code=0,
                response_body="",
                response_headers={},
                elapsed_ms=round(elapsed, 2),
                error=str(e),
                url=url,
            )


async def _send_one(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    url: str,
    payload: str,
    param: str,
    method: str,
) -> SendResult:
    """send a single payload via the specified method"""
    async with semaphore:
        start = time.monotonic()
        try:
            if method.upper() == "GET":
                injected_url = _inject_param_get(url, param, payload)
                resp = await client.get(injected_url)
                final_url = injected_url
            else:
                form_data = {param: payload}
                resp = await client.post(url, data=form_data)
                final_url = url

            elapsed = (time.monotonic() - start) * 1000

            return SendResult(
                payload=payload,
                target_param=param,
                method=method,
                status_code=resp.status_code,
                response_body=resp.text,
                response_headers=dict(resp.headers),
                elapsed_ms=round(elapsed, 2),
                url=final_url,
            )
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return SendResult(
                payload=payload,
                target_param=param,
                method=method,
                status_code=0,
                response_body="",
                response_headers={},
                elapsed_ms=round(elapsed, 2),
                error=str(e),
                url=url,
            )


async def send_stored_payloads(
    store_url: str,
    display_url: str,
    payloads: list[dict],
    form_fields: dict[str, str],
    timeout_ms: int = 10000,
    concurrency: int = 5,
) -> SendBatch:
    """
    Stored XSS mode: for each payload, POST to store_url with all form_fields
    (plus payload injected into target_param), then GET display_url and return
    that response body for reflection checking.

    Handles CSRF by fetching display_url before each submission to extract a
    fresh token from the form's hidden csrf input.
    """
    import re as _re
    batch = SendBatch()
    semaphore = asyncio.Semaphore(concurrency)
    timeout_s = timeout_ms / 1000

    async with httpx.AsyncClient(
        headers=DEFAULT_HEADERS,
        timeout=httpx.Timeout(timeout_s, connect=5.0),
        follow_redirects=True,
        verify=False,
    ) as client:

        async def _send_stored_one(payload_text: str, param: str) -> SendResult:
            async with semaphore:
                start = time.monotonic()
                try:
                    # 1. Fetch display page to get fresh CSRF token
                    csrf_resp = await client.get(display_url)
                    csrf_token = _extract_csrf(csrf_resp.text)

                    # 2. Build full form submission
                    post_data = dict(form_fields)  # clone defaults
                    if csrf_token:
                        post_data["csrf"] = csrf_token
                    post_data[param] = payload_text  # inject payload

                    # 3. POST to store URL
                    submit_resp = await client.post(store_url, data=post_data)
                    logger.debug(
                        f"stored submit {store_url} param={param} "
                        f"status={submit_resp.status_code}"
                    )

                    # 4. Fetch display page to check for reflection
                    display_resp = await client.get(display_url)
                    elapsed = (time.monotonic() - start) * 1000

                    return SendResult(
                        payload=payload_text,
                        target_param=param,
                        method="STORED_POST",
                        status_code=display_resp.status_code,
                        response_body=display_resp.text,
                        response_headers=dict(display_resp.headers),
                        elapsed_ms=round(elapsed, 2),
                        url=display_url,
                    )
                except Exception as e:
                    elapsed = (time.monotonic() - start) * 1000
                    logger.warning(f"stored send error param={param}: {e}")
                    return SendResult(
                        payload=payload_text,
                        target_param=param,
                        method="STORED_POST",
                        status_code=0,
                        response_body="",
                        response_headers={},
                        elapsed_ms=round(elapsed, 2),
                        error=str(e),
                        url=store_url,
                    )

        tasks = []
        for entry in payloads:
            payload_text = entry.get("payload", "")
            param = entry.get("target_param", "")
            tasks.append(_send_stored_one(payload_text, param))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, SendResult):
                batch.results.append(r)
                batch.total_sent += 1
                if r.error:
                    batch.total_errors += 1
            elif isinstance(r, Exception):
                batch.total_errors += 1
                logger.warning(f"stored send error: {r}")

    logger.info(
        f"stored: sent {batch.total_sent} requests, {batch.total_errors} errors"
    )
    return batch


def _extract_csrf(html: str) -> str:
    """Extract CSRF token from a hidden form input."""
    import re as _re
    # Match <input ... name="csrf" ... value="TOKEN">
    m = _re.search(
        r'<input[^>]*name=["\']csrf["\'][^>]*value=["\']([^"\']+)["\']',
        html,
        _re.IGNORECASE,
    )
    if m:
        return m.group(1)
    # Try reversed order: value before name
    m = _re.search(
        r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']csrf["\']',
        html,
        _re.IGNORECASE,
    )
    if m:
        return m.group(1)
    return ""


def _inject_param_get(url: str, param: str, value: str) -> str:
    """inject payload value into a url query parameter"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
