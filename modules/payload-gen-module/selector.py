"""
selector — filters payloads from the bank by reflection context type and allowed chars
maps context module output to the appropriate ai training labels for bank lookup
"""

import logging
import re

from bank import PayloadBank, PayloadEntry

logger = logging.getLogger(__name__)

# map reflection contexts (from context module) to dataset context labels
CONTEXT_TO_LABELS: dict[str, list[str]] = {
    # html body reflection is often directly exploitable via <script> or event-based tags.
    # include script_injection so verification can confirm execution on simple reflected pages.
    "html_body": ["script_injection", "tag_injection", "event_handler", "generic"],
    # attribute reflection usually requires breaking out of the attribute and injecting a tag
    # that auto-executes (e.g. <img onerror=...>) to be reliably confirmable.
    "attribute": [
        "attribute_escape",
        "tag_injection",
        "script_injection",
        "event_handler",
        "generic",
    ],
    "js_string": ["script_injection", "template_injection"],
    "js_block": ["script_injection", "dom_sink", "template_injection"],
    "url": ["js_uri"],
    "none": [],
}


def select_payloads(
    bank: PayloadBank,
    param: str,
    reflects_in: str,
    allowed_chars: list[str],
    max_payloads: int = 50,
) -> list[dict]:
    """
    select payloads from the bank that match the reflection context
    and are compatible with the allowed characters.
    """
    if reflects_in == "none" or reflects_in not in CONTEXT_TO_LABELS:
        logger.debug(f"param={param} context={reflects_in} — no payloads applicable")
        return []

    target_labels = CONTEXT_TO_LABELS[reflects_in]
    candidates: list[PayloadEntry] = []

    # NOTE: PayloadBank.query returns results in dataset (CSV) order.
    # Query deeper than the final max_payloads so we can later sort/choose higher-signal
    # payloads (e.g., auto-triggering vectors) instead of being stuck with the first N rows.
    per_label_limit = min(max(max_payloads * 50, 200), 2000)

    for label in target_labels:
        entries = bank.query(context=label, limit=per_label_limit)
        candidates.extend(entries)

    # deduplicate by payload text
    seen = set()
    unique: list[PayloadEntry] = []
    for entry in candidates:
        if entry.payload not in seen:
            seen.add(entry.payload)
            unique.append(entry)

    # filter by allowed chars — payload must only use chars that survive sanitization
    compatible = _filter_by_allowed_chars(unique, allowed_chars)

    # if too few compatible payloads, fall back to unfiltered
    if len(compatible) < 5 and len(unique) > 0:
        logger.debug(
            f"param={param} only {len(compatible)} compatible payloads, "
            f"including unfiltered candidates"
        )
        compatible = unique

    # To avoid any single label dominating (especially with skewed datasets), rank within each
    # label and then round-robin across labels.
    severity_order = {"high": 0, "medium": 1, "low": 2}
    prefer_auto_trigger = reflects_in in {"attribute", "html_body"}

    by_label: dict[str, list[PayloadEntry]] = {label: [] for label in target_labels}
    extras: list[PayloadEntry] = []
    for entry in compatible:
        if entry.context in by_label:
            by_label[entry.context].append(entry)
        else:
            extras.append(entry)

    def _entry_sort_key(e: PayloadEntry):
        return (
            0 if (prefer_auto_trigger and _is_auto_trigger_payload(e.payload)) else 1,
            severity_order.get(e.severity, 1),
            e.length,
        )

    for label in target_labels:
        by_label[label].sort(key=_entry_sort_key)
    extras.sort(key=_entry_sort_key)

    selected: list[PayloadEntry] = []
    selected_payloads: set[str] = set()

    made_progress = True
    while len(selected) < max_payloads and made_progress:
        made_progress = False
        for label in target_labels:
            if len(selected) >= max_payloads:
                break
            if not by_label[label]:
                continue
            candidate = by_label[label].pop(0)
            if candidate.payload in selected_payloads:
                continue
            selected_payloads.add(candidate.payload)
            selected.append(candidate)
            made_progress = True

    # If we still have budget, fill from any remaining extras.
    if len(selected) < max_payloads:
        for candidate in extras:
            if len(selected) >= max_payloads:
                break
            if candidate.payload in selected_payloads:
                continue
            selected_payloads.add(candidate.payload)
            selected.append(candidate)

    logger.info(
        f"param={param} context={reflects_in} selected={len(selected)} "
        f"from {len(candidates)} candidates"
    )

    return [
        {
            "payload": e.payload,
            "context": e.context,
            "severity": e.severity,
            "technique": e.technique,
            "length": e.length,
        }
        for e in selected
    ]


def _filter_by_allowed_chars(
    entries: list[PayloadEntry],
    allowed_chars: list[str],
) -> list[PayloadEntry]:
    """keep only payloads whose special chars are all in the allowed set"""
    if not allowed_chars:
        return entries  # no info about filtering, keep all

    special = set('<>"\'/()`{};&|=\\')
    allowed_set = set(allowed_chars)

    compatible: list[PayloadEntry] = []
    for entry in entries:
        # find which special chars this payload uses
        used_special = {ch for ch in entry.payload if ch in special}
        # all used special chars must be in allowed set
        if used_special.issubset(allowed_set):
            compatible.append(entry)

    return compatible


_AUTO_TRIGGER_RE = re.compile(
    r"(\bonerror\s*=|\bonload\s*=|<script\b|javascript:|data:text/html)",
    re.IGNORECASE,
)


def _is_auto_trigger_payload(text: str) -> bool:
    return bool(_AUTO_TRIGGER_RE.search(text))
