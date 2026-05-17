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
    attr_name: str = ""  # the attribute name when position is "attribute"


# HTML attributes that can execute javascript: URIs when the value is set directly
# (e.g., <a href="javascript:alert(1)">, <iframe src="javascript:...">)
EXECUTABLE_ATTRS = {
    "href", "src", "action", "formaction", "data",
    "xlink:href", "xlink:actuate", "xlink:show",
    "background", "longdesc", "poster",  # deprecated but still exploitable in some browsers
}

# Safe attributes where javascript: URIs cannot execute
SAFE_ATTRS = {
    "value", "title", "alt", "placeholder", "name", "id", "class",
    "style", "width", "height", "type", "checked", "disabled",
    "readonly", "required", "selected", "multiple",
    "role", "aria-", "data-",
    "min", "max", "step", "pattern", "autocomplete",
    "rel", "target", "download", "hreflang", "media",
    "lang", "dir", "hidden", "tabindex",
    "accesskey", "contenteditable", "draggable", "spellcheck",
    "translate", "color", "size", "rows", "cols",
    "wrap", "maxlength", "minlength", "autofocus",
    "accept", "capture", "inputmode", "list",
}


def is_safe_attribute(attr_name: str) -> bool:
    """Check if an attribute is safe (javascript: URIs cannot execute here)."""
    attr_lower = attr_name.lower().strip().lstrip("-")
    if attr_lower in EXECUTABLE_ATTRS:
        return False
    if attr_lower in SAFE_ATTRS:
        return True
    # data-* and aria-* are always safe
    if attr_lower.startswith("data-") or attr_lower.startswith("aria-"):
        return True
    # Unknown attributes are treated as safe (conservative)
    return True


# javascript: / data: URI prefix patterns — these URIs are special because they
# only execute in executable attributes (href, src, action, etc).  In body text
# or safe attributes (value, title, alt) they are inert text.
_JS_URI_PREFIXES = ("javascript:", "data:text/html", "data:text/javascript")


def is_js_uri_safe_in_context(payload: str, position: str, attr_name: str = "") -> bool:
    """
    Check whether a javascript:/data: URI payload is SAFE (cannot execute) in the
    given reflection context.

    Returns True when the payload is safe (don't mark as vuln).
    Returns False when the payload is dangerous (CAN execute — should mark as vuln).

    This implements the Tier 2 exception logic: javascript:/data: URIs only execute
    in executable attributes (href, src, action).  In body text or safe attributes
    (value, title, alt) they are inert text, not exploitable.

    For non-JS-URI payloads (e.g. ``<script>alert(1)</script>``), returns False
    (dangerous) so the standard position-based check applies.
    """
    payload_lower = payload.lower().strip()
    if not payload_lower.startswith(_JS_URI_PREFIXES):
        # Not a javascript:/data: URI — existing position-based rules apply
        return False

    if position == "html_body":
        # javascript: URIs in body text are inert text, not executable
        return True
    elif position == "attribute" and attr_name:
        return is_safe_attribute(attr_name)
    # script and style positions are still dangerous for JS URIs
    return False


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
    position, attr_name = _find_position(payload, response_body)

    # extract context snippet
    snippet = _extract_snippet(payload, response_body)

    return ReflectionResult(
        reflected=True,
        position=position,
        exact_match=exact,
        decoded_match=decoded,
        context_snippet=snippet,
        attr_name=attr_name,
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
            "attr_name": reflection.attr_name,
        })

    reflected_count = sum(1 for c in checked if c["reflected"])
    logger.info(f"reflection check: {reflected_count}/{len(checked)} reflected")
    return checked


def _find_position(payload: str, body: str) -> tuple[str, str]:
    """determine where in the html the payload is reflected.
    returns (position, attribute_name) where attribute_name is populated when position is 'attribute'.
    """
    try:
        soup = BeautifulSoup(body, "lxml")
    except Exception:
        soup = BeautifulSoup(body, "html.parser")

    payload_lower = payload.lower()

    # check inside script tags (most dangerous — highest priority)
    for script in soup.find_all("script"):
        if script.string and payload_lower in script.string.lower():
            return ("script", "")

    # check inside html comments
    comments = body.count("<!--")
    if comments > 0:
        comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
        for match in comment_pattern.finditer(body):
            if payload_lower in match.group(1).lower():
                return ("comment", "")

    # check inside attributes
    attr_name_found = ""
    for tag in soup.find_all(True):
        for attr_name, attr_val in (tag.attrs or {}).items():
            val_str = str(attr_val) if not isinstance(attr_val, str) else attr_val
            if payload_lower in val_str.lower():
                attr_name_found = attr_name
                break
        if attr_name_found:
            break

    # check inside style tags
    for style in soup.find_all("style"):
        if style.string and payload_lower in style.string.lower():
            # Payload in style AND attribute — style takes higher priority
            return ("style", "")

    # check if payload is also in html body
    in_body = payload_lower in body.lower()

    if attr_name_found:
        # Check if payload is also in the HTML body (outside of attribute)
        # The body check above includes attributes, so we need a more precise check:
        # Remove all tag content and check again
        body_text = soup.get_text(separator=" ", strip=True)
        if payload_lower in body_text.lower():
            # Payload is in BOTH body and attribute — body is more dangerous
            return ("html_body", attr_name_found)
        # Only in attribute
        return ("attribute", attr_name_found)

    # default: reflected in html body
    if in_body:
        return ("html_body", "")

    return ("none", "")


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
