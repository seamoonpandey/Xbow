#!/usr/bin/env python3
"""
Unit tests for the Tier 2 javascript:/data: URI filter in
modules/fuzzer-module/reflection_checker.py

Validates that javascript:/data: URI payloads are correctly classified as
safe or dangerous depending on their reflection context (position + attribute).
"""

import sys
from pathlib import Path

# Add fuzzer-module to path for import
MODULE_DIR = Path(__file__).resolve().parent.parent / "modules" / "fuzzer-module"
sys.path.insert(0, str(MODULE_DIR))

from reflection_checker import is_js_uri_safe_in_context


# ── Payloads that ARE javascript: / data: URIs ────────────────────────


def test_javascript_uri_in_body_is_safe():
    """javascript: URI in html_body is inert text — safe"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "html_body"
    ) is True


def test_javascript_data_uri_in_body_is_safe():
    """data:text/html URI in html_body is inert text — safe"""
    assert is_js_uri_safe_in_context(
        "data:text/html,<script>alert(1)</script>", "html_body"
    ) is True


def test_javascript_data_text_javascript_in_body_is_safe():
    """data:text/javascript URI in html_body is inert text — safe"""
    assert is_js_uri_safe_in_context(
        "data:text/javascript,alert(1)", "html_body"
    ) is True


def test_javascript_uri_in_value_attr_is_safe():
    """javascript: URI in a value attribute is safe"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "value"
    ) is True


def test_javascript_uri_in_href_attr_is_dangerous():
    """javascript: URI in href attribute CAN execute"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "href"
    ) is False


def test_javascript_uri_in_src_attr_is_dangerous():
    """javascript: URI in src attribute CAN execute"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "src"
    ) is False


def test_javascript_uri_in_action_attr_is_dangerous():
    """javascript: URI in form action attribute CAN execute"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "action"
    ) is False


def test_javascript_uri_in_formaction_attr_is_dangerous():
    """javascript: URI in formaction attribute CAN execute"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "formaction"
    ) is False


def test_javascript_uri_in_data_attr_is_dangerous():
    """javascript: URI in data attribute (object tag) CAN execute"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "data"
    ) is False


def test_javascript_uri_in_xlink_href_attr_is_dangerous():
    """javascript: URI in xlink:href (SVG) CAN execute"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "xlink:href"
    ) is False


def test_javascript_uri_in_style_attr_is_safe():
    """javascript: URI in style attribute (used as CSS value) is safe"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "style"
    ) is True


def test_javascript_uri_in_title_attr_is_safe():
    """javascript: URI in title attribute is safe"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "title"
    ) is True


def test_javascript_uri_in_alt_attr_is_safe():
    """javascript: URI in alt attribute is safe"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "alt"
    ) is True


def test_javascript_uri_in_class_attr_is_safe():
    """javascript: URI in class attribute is safe"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "class"
    ) is True


def test_javascript_uri_in_placeholder_attr_is_safe():
    """javascript: URI in placeholder attribute is safe"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "placeholder"
    ) is True


def test_javascript_uri_in_id_attr_is_safe():
    """javascript: URI in id attribute is safe"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "id"
    ) is True


def test_javascript_uri_in_name_attr_is_safe():
    """javascript: URI in name attribute is safe"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", "name"
    ) is True


# ── Javascript: URI in script / style positions ───────────────────────


def test_javascript_uri_in_script_position_is_dangerous():
    """javascript: URI in script context CAN execute"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "script"
    ) is False


def test_javascript_uri_in_style_position_is_dangerous():
    """javascript: URI in style context CAN execute"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "style"
    ) is False


# ── Non-JS-URI payloads (should return False = dangerous) ─────────────


def test_html_script_tag_in_body_is_dangerous():
    """<script>alert(1)</script> is NOT a JS URI — standard rules apply (dangerous)"""
    assert is_js_uri_safe_in_context(
        "<script>alert(1)</script>", "html_body"
    ) is False


def test_event_handler_in_body_is_dangerous():
    """onerror=alert(1) is NOT a JS URI — standard rules apply"""
    assert is_js_uri_safe_in_context(
        "<img src=x onerror=alert(1)>", "html_body"
    ) is False


def test_event_handler_in_attribute_is_dangerous():
    """onfocus=alert(1) is NOT a JS URI — standard rules apply"""
    assert is_js_uri_safe_in_context(
        "<input onfocus=alert(1)>", "attribute", "value"
    ) is False


def test_svg_payload_is_dangerous():
    """<svg onload=alert(1)> is NOT a JS URI — standard rules apply"""
    assert is_js_uri_safe_in_context(
        "<svg onload=alert(1)>", "html_body"
    ) is False


def test_plain_html_tag_is_dangerous():
    """<b>hello</b> is NOT a JS URI — standard rules apply"""
    assert is_js_uri_safe_in_context(
        "<b>hello</b>", "html_body"
    ) is False


# ── Edge cases: attribute without attr_name ──────────────────────────


def test_javascript_uri_in_attribute_no_attr_name():
    """javascript: URI in attribute position but no attr_name — conservative: dangerous"""
    assert is_js_uri_safe_in_context(
        "javascript:alert(1)", "attribute", ""
    ) is False


def test_data_uri_in_attribute_no_attr_name():
    """data:text/html URI in attribute position but no attr_name — conservative"""
    assert is_js_uri_safe_in_context(
        "data:text/html,<script>alert(1)</script>", "attribute", ""
    ) is False


# ── Case sensitivity and whitespace ──────────────────────────────────


def test_javascript_uppercase_uri():
    """JAVASCRIPT: (uppercase) should still be detected"""
    assert is_js_uri_safe_in_context(
        "JAVASCRIPT:alert(1)", "html_body"
    ) is True


def test_javascript_mixed_case_uri():
    """JavaScript: (mixed case) should still be detected"""
    assert is_js_uri_safe_in_context(
        "JavaScript:alert(1)", "html_body"
    ) is True


def test_javascript_uri_with_leading_whitespace():
    """Leading whitespace should be stripped before JS URI detection"""
    assert is_js_uri_safe_in_context(
        "  javascript:alert(1)", "html_body"
    ) is True


# ── Full decision matrix smoke test ──────────────────────────────────


def test_javascript_decision_matrix():
    """
    Smoke test covering the full decision matrix for javascript:alert(1):
    position x attribute → expected safe-or-dangerous outcome.
    """
    payload = "javascript:alert(1)"
    matrix = [
        # (position, attr_name, expected_safe)
        ("html_body",    "",          True),    # inert text
        ("attribute",    "href",      False),   # executable
        ("attribute",    "src",       False),   # executable
        ("attribute",    "action",    False),   # executable
        ("attribute",    "formaction", False),  # executable
        ("attribute",    "data",      False),   # executable (object tag)
        ("attribute",    "value",     True),    # safe
        ("attribute",    "title",     True),    # safe
        ("attribute",    "alt",       True),    # safe
        ("attribute",    "placeholder", True),  # safe
        ("attribute",    "id",        True),    # safe
        ("attribute",    "name",      True),    # safe
        ("attribute",    "class",     True),    # safe
        ("attribute",    "style",     True),    # safe (CSS, not URI context)
        ("script",       "",          False),   # dangerous
        ("style",        "",          False),   # dangerous
    ]
    for position, attr_name, expected_safe in matrix:
        result = is_js_uri_safe_in_context(payload, position, attr_name)
        assert result is expected_safe, (
            f"Mismatch for position={position!r}, attr_name={attr_name!r}: "
            f"expected {expected_safe}, got {result}"
        )


def test_data_uri_decision_matrix():
    """
    Smoke test for data:text/html,<script>alert(1)</script> across the matrix.
    Should behave identically to javascript: URIs.
    """
    payload = "data:text/html,<script>alert(1)</script>"
    matrix = [
        ("html_body", "", True),
        ("attribute", "href", False),
        ("attribute", "value", True),
        ("script", "", False),
    ]
    for position, attr_name, expected_safe in matrix:
        result = is_js_uri_safe_in_context(payload, position, attr_name)
        assert result is expected_safe, (
            f"Data URI mismatch for position={position!r}, attr_name={attr_name!r}: "
            f"expected {expected_safe}, got {result}"
        )
