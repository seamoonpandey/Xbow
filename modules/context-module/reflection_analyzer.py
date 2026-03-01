"""
reflection analyzer — checks where and how the probe marker appears in the response
"""

import logging
import re

logger = logging.getLogger(__name__)


def analyze_reflection(body: str, marker: str) -> list[dict]:
    """
    find all occurrences of the marker in the response body.
    returns a list of reflection points with position context.
    """
    reflections: list[dict] = []
    if not marker or marker not in body:
        return reflections

    # find all occurrences
    start = 0
    while True:
        idx = body.find(marker, start)
        if idx == -1:
            break

        # extract surrounding context (100 chars each side)
        ctx_start = max(0, idx - 100)
        ctx_end = min(len(body), idx + len(marker) + 100)
        context_snippet = body[ctx_start:ctx_end]

        # determine position type based on surrounding html
        position = _classify_position(body, idx, marker)

        reflections.append({
            "index": idx,
            "position": position,
            "context_snippet": context_snippet,
        })

        start = idx + len(marker)

    logger.debug(f"marker={marker} found {len(reflections)} reflections")
    return reflections


def _classify_position(body: str, idx: int, marker: str) -> str:
    """classify the reflection position based on surrounding html context"""
    # look backwards for the nearest tag context
    before = body[max(0, idx - 500):idx]
    after = body[idx + len(marker):min(len(body), idx + len(marker) + 500)]

    # check if inside a script tag
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open > last_script_close:
        # inside a <script> block
        # check if inside a string literal
        quote_before = before[last_script_open:]
        single_quotes = quote_before.count("'") % 2
        double_quotes = quote_before.count('"') % 2
        if single_quotes == 1 or double_quotes == 1:
            return "js_string"
        return "js_block"

    # check if inside an html attribute
    last_tag_open = before.rfind("<")
    last_tag_close = before.rfind(">")
    if last_tag_open > last_tag_close:
        # we are inside an html tag
        tag_content = before[last_tag_open:]
        # check for attribute assignment pattern
        if re.search(r'=\s*["\'][^"\']*$', tag_content):
            return "attribute"
        if re.search(r'=\s*$', tag_content):
            return "attribute"

    # check if inside href/src (url context)
    if re.search(r'(?:href|src|action)\s*=\s*["\'][^"\']*$', before, re.IGNORECASE):
        return "url"

    # check if inside a style tag
    last_style_open = before.rfind("<style")
    last_style_close = before.rfind("</style")
    if last_style_open > last_style_close:
        return "none"  # css context, not exploitable in same way

    # check if inside a comment
    last_comment_open = before.rfind("<!--")
    last_comment_close = before.rfind("-->")
    if last_comment_open > last_comment_close:
        return "none"

    # default: html body
    return "html_body"


def get_primary_context(reflections: list[dict]) -> str:
    """return the most exploitable reflection context"""
    if not reflections:
        return "none"

    # priority order for exploitation
    priority = ["js_string", "js_block", "attribute", "url", "html_body", "none"]

    positions = [r["position"] for r in reflections]
    for ctx in priority:
        if ctx in positions:
            return ctx

    return "none"
