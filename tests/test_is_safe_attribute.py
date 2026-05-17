#!/usr/bin/env python3
"""
Unit tests for is_safe_attribute() in modules/fuzzer-module/reflection_checker.py

Validates the safe-attribute logic used by the Tier 2 javascript: URI filter
to reduce false positives on HTML-escaped pages.
"""

import sys
from pathlib import Path

# Add fuzzer-module to path for import
MODULE_DIR = Path(__file__).resolve().parent.parent / "modules" / "fuzzer-module"
sys.path.insert(0, str(MODULE_DIR))

from reflection_checker import is_safe_attribute, EXECUTABLE_ATTRS, SAFE_ATTRS


# ── Executable attributes (javascript: URIs CAN execute here) ─────────────

def test_href_is_executable():
    """href is executable — javascript: URIs can execute"""
    assert is_safe_attribute("href") is False


def test_src_is_executable():
    """src is executable — javascript: URIs can execute"""
    assert is_safe_attribute("src") is False


def test_action_is_executable():
    """action (form) is executable"""
    assert is_safe_attribute("action") is False


def test_formaction_is_executable():
    """formaction is executable"""
    assert is_safe_attribute("formaction") is False


def test_data_attr_is_executable():
    """data attribute (object) is executable"""
    assert is_safe_attribute("data") is False


def test_xlink_href_is_executable():
    """xlink:href (SVG) is executable"""
    assert is_safe_attribute("xlink:href") is False


def test_background_is_executable():
    """deprecated background attribute is executable in some browsers"""
    assert is_safe_attribute("background") is False


def test_longdesc_is_executable():
    """deprecated longdesc is executable in some browsers"""
    assert is_safe_attribute("longdesc") is False


def test_poster_is_executable():
    """deprecated poster (video) is executable in some browsers"""
    assert is_safe_attribute("poster") is False


# ── Safe attributes (javascript: URIs cannot execute here) ───────────────

def test_value_is_safe():
    """value attribute is safe"""
    assert is_safe_attribute("value") is True


def test_title_is_safe():
    """title attribute is safe"""
    assert is_safe_attribute("title") is True


def test_alt_is_safe():
    """alt attribute is safe"""
    assert is_safe_attribute("alt") is True


def test_placeholder_is_safe():
    """placeholder attribute is safe"""
    assert is_safe_attribute("placeholder") is True


def test_name_is_safe():
    """name attribute is safe"""
    assert is_safe_attribute("name") is True


def test_id_is_safe():
    """id attribute is safe"""
    assert is_safe_attribute("id") is True


def test_class_is_safe():
    """class attribute is safe"""
    assert is_safe_attribute("class") is True


def test_style_is_safe():
    """style attribute (when used for javascript: URI) is safe"""
    assert is_safe_attribute("style") is True


def test_type_is_safe():
    """type attribute is safe"""
    assert is_safe_attribute("type") is True


def test_checked_is_safe():
    """checked attribute is safe"""
    assert is_safe_attribute("checked") is True


def test_readonly_is_safe():
    """readonly attribute is safe"""
    assert is_safe_attribute("readonly") is True


def test_required_is_safe():
    """required attribute is safe"""
    assert is_safe_attribute("required") is True


def test_rel_is_safe():
    """rel attribute is safe"""
    assert is_safe_attribute("rel") is True


def test_target_is_safe():
    """target attribute is safe"""
    assert is_safe_attribute("target") is True


def test_download_is_safe():
    """download attribute is safe"""
    assert is_safe_attribute("download") is True


def test_hidden_is_safe():
    """hidden attribute is safe"""
    assert is_safe_attribute("hidden") is True


def test_tabindex_is_safe():
    """tabindex attribute is safe"""
    assert is_safe_attribute("tabindex") is True


def test_lang_is_safe():
    """lang attribute is safe"""
    assert is_safe_attribute("lang") is True


def test_dir_is_safe():
    """dir attribute is safe"""
    assert is_safe_attribute("dir") is True


# ── data-* and aria-* attributes ────────────────────────────────────────

def test_data_custom_is_safe():
    """data-* attributes are always safe"""
    assert is_safe_attribute("data-custom") is True
    assert is_safe_attribute("data-target") is True
    assert is_safe_attribute("data-toggle") is True


def test_aria_custom_is_safe():
    """aria-* attributes are always safe"""
    assert is_safe_attribute("aria-label") is True
    assert is_safe_attribute("aria-hidden") is True
    assert is_safe_attribute("aria-expanded") is True


# ── Unknown attributes (conservative: default to safe) ──────────────────

def test_unknown_attribute_is_safe():
    """Unknown attributes default to safe (conservative)"""
    assert is_safe_attribute("something-else") is True
    assert is_safe_attribute("custom-attr") is True
    assert is_safe_attribute("random") is True


# ── Case insensitivity ──────────────────────────────────────────────────

def test_case_insensitive_href():
    """Case should not matter — HREF is still executable"""
    assert is_safe_attribute("HREF") is False
    assert is_safe_attribute("Href") is False
    assert is_safe_attribute("href") is False


def test_case_insensitive_value():
    """Case should not matter — VALUE is still safe"""
    assert is_safe_attribute("VALUE") is True
    assert is_safe_attribute("Value") is True


def test_case_insensitive_data_custom():
    """Case should not matter — DATA-CUSTOM is still safe"""
    assert is_safe_attribute("DATA-CUSTOM") is True
    assert is_safe_attribute("Data-Toggle") is True


# ── Whitespace and dash normalization ───────────────────────────────────

def test_whitespace_stripped():
    """Leading/trailing whitespace should be stripped"""
    assert is_safe_attribute(" href ") is False
    assert is_safe_attribute("  value  ") is True


def test_leading_dash_stripped():
    """Leading dashes (from data binding like -value) should be stripped"""
    assert is_safe_attribute("-href") is False
    assert is_safe_attribute("-value") is True
    assert is_safe_attribute("--href") is False
    assert is_safe_attribute("--value") is True


# ── Verifying the sets are complete ─────────────────────────────────────

def test_all_executable_attrs_are_listed():
    """Every attribute in EXECUTABLE_ATTRS should return False"""
    for attr in EXECUTABLE_ATTRS:
        assert is_safe_attribute(attr) is False, f"{attr} should be executable"


def test_all_safe_attrs_are_listed():
    """Every attribute in SAFE_ATTRS should return True"""
    for attr in SAFE_ATTRS:
        assert is_safe_attribute(attr) is True, f"{attr} should be safe"


# ── Executable attributes NOT in the wrong set ──────────────────────────

def test_no_overlap_between_sets():
    """No attribute should appear in both EXECUTABLE_ATTRS and SAFE_ATTRS"""
    overlap = EXECUTABLE_ATTRS & SAFE_ATTRS
    assert len(overlap) == 0, f"Overlap found: {overlap}"
