"""
html parser — identifies the exact DOM position of reflected markers using beautifulsoup
"""

import logging
from dataclasses import dataclass

from bs4 import BeautifulSoup, Comment, NavigableString, Tag

logger = logging.getLogger(__name__)


@dataclass
class ReflectionPoint:
    element: str
    attribute: str | None
    parent_tag: str
    context: str
    path: str


def parse_reflection_points(html: str, marker: str) -> list[ReflectionPoint]:
    """
    parse the html and find all locations where the marker appears.
    returns structured reflection points with dom path info.
    """
    if marker not in html:
        return []

    soup = BeautifulSoup(html, "lxml")
    points: list[ReflectionPoint] = []

    # search text nodes
    for text_node in soup.find_all(string=lambda t: t and marker in t):
        parent = text_node.parent
        if parent is None:
            continue

        if isinstance(text_node, Comment):
            points.append(ReflectionPoint(
                element="comment",
                attribute=None,
                parent_tag=parent.name if isinstance(parent, Tag) else "unknown",
                context="none",
                path=_build_path(parent),
            ))
        elif isinstance(parent, Tag) and parent.name == "script":
            points.append(ReflectionPoint(
                element="script",
                attribute=None,
                parent_tag="script",
                context="js_block",
                path=_build_path(parent),
            ))
        elif isinstance(parent, Tag) and parent.name == "style":
            points.append(ReflectionPoint(
                element="style",
                attribute=None,
                parent_tag="style",
                context="none",
                path=_build_path(parent),
            ))
        else:
            points.append(ReflectionPoint(
                element="text",
                attribute=None,
                parent_tag=parent.name if isinstance(parent, Tag) else "unknown",
                context="html_body",
                path=_build_path(parent),
            ))

    # search attributes
    for tag in soup.find_all(True):
        if not isinstance(tag, Tag):
            continue
        for attr, value in tag.attrs.items():
            val_str = value if isinstance(value, str) else " ".join(value)
            if marker in val_str:
                ctx = _classify_attribute_context(tag.name, attr)
                points.append(ReflectionPoint(
                    element=tag.name,
                    attribute=attr,
                    parent_tag=tag.parent.name if isinstance(tag.parent, Tag) else "root",
                    context=ctx,
                    path=_build_path(tag),
                ))

    logger.debug(f"found {len(points)} reflection points for marker={marker}")
    return points


def _classify_attribute_context(tag_name: str, attr_name: str) -> str:
    """classify the context based on which attribute contains the reflection"""
    url_attrs = {"href", "src", "action", "formaction", "data", "codebase", "cite", "poster"}
    event_attrs = {
        "onclick", "onload", "onerror", "onmouseover", "onfocus",
        "onblur", "onsubmit", "onchange", "oninput", "onkeydown",
        "onkeyup", "onkeypress", "onmousedown", "onmouseup",
    }

    attr_lower = attr_name.lower()

    if attr_lower in url_attrs:
        return "url"
    if attr_lower in event_attrs or attr_lower.startswith("on"):
        return "js_string"
    if attr_lower == "style":
        return "none"

    return "attribute"


def _build_path(element) -> str:
    """build a css-like path to the element"""
    parts: list[str] = []
    current = element
    while current and hasattr(current, "name"):
        if not isinstance(current, Tag):
            break
        name = current.name
        if name == "[document]":
            break
        # add id or class for specificity
        el_id = current.get("id")
        if el_id:
            parts.append(f"{name}#{el_id}")
        else:
            parts.append(name)
        current = current.parent
    return " > ".join(reversed(parts)) if parts else "unknown"


def get_dom_context(html: str, marker: str) -> str:
    """convenience: return the primary context from dom parsing"""
    points = parse_reflection_points(html, marker)
    if not points:
        return "none"

    # prioritize exploitable contexts
    priority = ["js_string", "js_block", "url", "attribute", "html_body", "none"]
    contexts = {p.context for p in points}
    for ctx in priority:
        if ctx in contexts:
            return ctx
    return "none"
