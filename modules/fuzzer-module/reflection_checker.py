"""
reflection_checker — verifies whether injected payloads appear in http responses
checks raw body, html attributes, script blocks, and dom structure
"""

import logging
import re
from dataclasses import dataclass
from html import unescape

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class ReflectionResult:
    """result of checking a single response for payload reflection"""
    reflected: bool
    position: str  # html_body, attribute, script, comment, none
    exact_match: bool
    decoded_match: bool
    context_snippet: str


def check_reflection(
    payload: str,
    response_body: str,
    param: str = "",
) -> ReflectionResult:
    """
    check if the payload is reflected in the response body.
    tries exact match, decoded match, and structural match.
    """
    if not response_body or not payload:
        return ReflectionResult(
            reflected=False,
            position="none",
            exact_match=False,
            decoded_match=False,
            context_snippet="",
        )

    # 1. exact string match
    exact = payload in response_body

    # 2. decoded match (html entities decoded)
    decoded_body = unescape(response_body)
    decoded = payload in decoded_body if not exact else False

    if not exact and not decoded:
        # 3. case-insensitive match
        if payload.lower() in response_body.lower():
            exact = True
        else:
            return ReflectionResult(
                reflected=False,
                position="none",
                exact_match=False,
                decoded_match=False,
                context_snippet="",
            )

    # determine reflection position
    position = _find_position(payload, response_body)

    # extract context snippet
    snippet = _extract_snippet(payload, response_body)

    return ReflectionResult(
        reflected=True,
        position=position,
        exact_match=exact,
        decoded_match=decoded,
        context_snippet=snippet,
    )


def check_reflection_batch(
    results: list[dict],
) -> list[dict]:
    """
    check reflection for a batch of send results.
    attaches reflection info to each result dict.
    """
    checked = []
    for r in results:
        payload = r.get("payload", "")
        body = r.get("response_body", "")
        param = r.get("target_param", "")

        reflection = check_reflection(payload, body, param)

        checked.append({
            **r,
            "reflected": reflection.reflected,
            "reflection_position": reflection.position,
            "exact_match": reflection.exact_match,
            "context_snippet": reflection.context_snippet,
        })

    reflected_count = sum(1 for c in checked if c["reflected"])
    logger.info(f"reflection check: {reflected_count}/{len(checked)} reflected")
    return checked


def _find_position(payload: str, body: str) -> str:
    """determine where in the html the payload is reflected"""
    try:
        soup = BeautifulSoup(body, "lxml")
    except Exception:
        soup = BeautifulSoup(body, "html.parser")

    payload_lower = payload.lower()

    # check inside script tags
    for script in soup.find_all("script"):
        if script.string and payload_lower in script.string.lower():
            return "script"

    # check inside html comments
    comments = body.count("<!--")
    if comments > 0:
        comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
        for match in comment_pattern.finditer(body):
            if payload_lower in match.group(1).lower():
                return "comment"

    # check inside attributes
    for tag in soup.find_all(True):
        for attr_name, attr_val in (tag.attrs or {}).items():
            val_str = str(attr_val) if not isinstance(attr_val, str) else attr_val
            if payload_lower in val_str.lower():
                return "attribute"

    # check inside style tags
    for style in soup.find_all("style"):
        if style.string and payload_lower in style.string.lower():
            return "style"

    # default: reflected in html body
    if payload_lower in body.lower():
        return "html_body"

    return "none"


def _extract_snippet(payload: str, body: str, context_chars: int = 80) -> str:
    """extract a snippet around the reflected payload for evidence"""
    idx = body.lower().find(payload.lower())
    if idx == -1:
        return ""

    start = max(0, idx - context_chars)
    end = min(len(body), idx + len(payload) + context_chars)
    snippet = body[start:end]

    # clean up for readability
    snippet = re.sub(r"\s+", " ", snippet).strip()
    if start > 0:
        snippet = "..." + snippet
    if end < len(body):
        snippet = snippet + "..."

    return snippet[:300]  # cap at 300 chars
