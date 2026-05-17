"""
probe injector — injects unique markers into each parameter to detect reflection
"""

import hashlib
import logging
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

logger = logging.getLogger(__name__)

MARKER_PREFIX = "rs0x"
FRAGMENT_PARAM = "__fragment__"


def generate_marker(param: str, salt: str = "redsentinel") -> str:
    """generate a unique probe marker for a parameter"""
    raw = f"{salt}:{param}"
    digest = hashlib.md5(raw.encode()).hexdigest()[:8]
    return f"{MARKER_PREFIX}{digest}"


def build_probe_url(url: str, param: str, marker: str) -> str:
    """replace or append the param value with the probe marker"""
    parsed = urlparse(url)
    if param == FRAGMENT_PARAM:
        return urlunparse(parsed._replace(fragment=marker))

    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [marker]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def inject_probes(
    url: str,
    params: list[str],
    timeout: float = 10.0,
    cookie_header: str | None = None,
) -> dict[str, dict]:
    """
    inject probe markers into each param and fetch the response.
    sends both GET (query string) and POST (form body) to cover form-based
    params that only reflect when submitted via POST.
    returns {param: {marker, status_code, body, headers}} for each param,
    using the response that actually reflects the marker (preferring POST
    for form fields, falling back to GET).

    when cookie_header is provided, it is forwarded as a Cookie header on
    all requests so the context module can probe authenticated endpoints.
    """
    results: dict[str, dict] = {}
    post_globally_supported: bool | None = None

    client_headers = {}
    if cookie_header:
        client_headers["Cookie"] = cookie_header

    async with httpx.AsyncClient(
        headers=client_headers or None,
        timeout=timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        for param in params:
            marker = generate_marker(param)
            probe_url = build_probe_url(url, param, marker)

            get_result = None
            post_result = None

            # Try GET first
            try:
                response = await client.get(probe_url)
                get_result = {
                    "marker": marker,
                    "status_code": response.status_code,
                    "body": response.text,
                    "headers": dict(response.headers),
                }
                logger.debug(f"probe GET param={param} marker={marker} status={response.status_code}")
            except Exception as e:
                logger.warning(f"probe GET failed param={param}: {e}")

            # Also try POST (form body) — many form params only reflect via POST
            if param != FRAGMENT_PARAM and post_globally_supported is not False:
                try:
                    # Parse the base URL without the probe query string
                    parsed = urlparse(url)
                    base_url = urlunparse(parsed._replace(query=""))
                    post_data = {param: marker}
                    response = await client.post(
                        base_url or url,
                        data=post_data,
                    )
                    post_result = {
                        "marker": marker,
                        "status_code": response.status_code,
                        "body": response.text,
                        "headers": dict(response.headers),
                    }
                    logger.debug(f"probe POST param={param} marker={marker} status={response.status_code}")

                    # Learn endpoint behavior once and avoid repeated 405/501/403 noise.
                    if response.status_code in (405, 501, 403):
                        post_globally_supported = False
                    else:
                        post_globally_supported = True
                except Exception as e:
                    logger.warning(f"probe POST failed param={param}: {e}")

            # Prefer whichever method reflected the marker.
            # POST is preferred for form fields; GET is the fallback.
            if post_result and marker in post_result.get("body", ""):
                post_result["probe_method"] = "post"
                results[param] = post_result
            elif get_result and marker in get_result.get("body", ""):
                get_result["probe_method"] = "get"
                results[param] = get_result
            elif get_result:
                get_result["probe_method"] = "get"
                results[param] = get_result
            elif post_result:
                post_result["probe_method"] = "post"
                results[param] = post_result
            else:
                results[param] = {
                    "marker": marker,
                    "status_code": 0,
                    "body": "",
                    "headers": {},
                    "probe_method": "none",
                }

    return results
