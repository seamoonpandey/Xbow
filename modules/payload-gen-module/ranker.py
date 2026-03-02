"""
ranker — scores and ranks generated payloads by execution probability
considers context fit, payload complexity, and obfuscation level
"""

import logging
import math
import re

logger = logging.getLogger(__name__)

# weights for each scoring component
WEIGHT_CONTEXT_FIT = 0.35
WEIGHT_COMPLEXITY = 0.25
WEIGHT_LENGTH = 0.15
WEIGHT_TECHNIQUE = 0.15
WEIGHT_CHAR_COVERAGE = 0.10

# context-specific patterns that boost score
CONTEXT_BOOSTERS: dict[str, list[str]] = {
    "script_injection": [r"<script", r"</script>"],
    "event_handler": [r"\bon\w+=", r"<\w+\s"],
    "js_uri": [r"javascript:", r"data:"],
    "tag_injection": [r"<\w+", r"/>"],
    # Reflection-in-attribute (as reported by the context module) is typically best exploited
    # by breaking out and using an auto-triggering handler (onerror/onload) on a tag.
    "attribute": [r"\bonerror\s*=|\bonload\s*=", r"<img\b|<svg\b|<script\b"],
    "template_injection": [r"\{\{", r"\}\}", r"\$\{"],
    "dom_sink": [r"document\.", r"\.innerHTML", r"eval\("],
    "attribute_escape": [r'"\s*\w+=', r"'\s*\w+=", r"\\"],
    "generic": [],
}

# technique effectiveness multipliers
TECHNIQUE_SCORES: dict[str, float] = {
    "original": 1.0,
    "mutated": 0.85,
    "obfuscated:unicode_escape": 0.80,
    "obfuscated:hex_escape": 0.75,
    "obfuscated:html_entity": 0.78,
    "obfuscated:url_encode": 0.70,
    "obfuscated:double_url_encode": 0.65,
    "obfuscated:mixed_case": 0.82,
    "obfuscated:tab_newline_inject": 0.72,
    "obfuscated:comment_inject": 0.68,
    "obfuscated:concat_split": 0.74,
}

# severity numeric values
SEVERITY_VALUES: dict[str, float] = {
    "high": 1.0,
    "medium": 0.7,
    "low": 0.4,
}


def rank_payloads(
    payloads: list[dict],
    context: str,
    allowed_chars: list[str] | None = None,
    limit: int | None = None,
) -> list[dict]:
    """
    score and rank payloads by estimated execution probability.
    attaches 'score' field to each payload dict.
    returns sorted list (highest score first), optionally limited.
    """
    scored: list[dict] = []

    for p in payloads:
        score = _compute_score(p, context, allowed_chars)
        scored.append({**p, "score": round(score, 4)})

    scored.sort(key=lambda x: x["score"], reverse=True)

    if limit:
        scored = scored[:limit]

    logger.info(
        f"ranked {len(payloads)} payloads for context={context}, "
        f"top score={scored[0]['score'] if scored else 0}"
    )
    return scored


def _compute_score(
    payload: dict,
    context: str,
    allowed_chars: list[str] | None,
) -> float:
    """compute composite score for a single payload"""
    text = payload.get("payload", "")
    technique = payload.get("technique", "original")
    severity = payload.get("severity", "medium")

    context_score = _score_context_fit(text, context)
    complexity_score = _score_complexity(text)
    length_score = _score_length(text)
    technique_score = _score_technique(technique)
    char_score = _score_char_coverage(text, allowed_chars) if allowed_chars else 1.0

    # severity bonus
    severity_bonus = SEVERITY_VALUES.get(severity, 0.5)

    total = (
        WEIGHT_CONTEXT_FIT * context_score
        + WEIGHT_COMPLEXITY * complexity_score
        + WEIGHT_LENGTH * length_score
        + WEIGHT_TECHNIQUE * technique_score
        + WEIGHT_CHAR_COVERAGE * char_score
    ) * severity_bonus

    return min(total, 1.0)


def _score_context_fit(text: str, context: str) -> float:
    """score how well the payload matches the target context"""
    patterns = CONTEXT_BOOSTERS.get(context, [])
    if not patterns:
        return 0.5

    matches = sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))
    return min(matches / len(patterns), 1.0)


def _score_complexity(text: str) -> float:
    """score payload complexity — more diverse structure scores higher"""
    features = 0
    if re.search(r"<\w+", text):
        features += 1
    if re.search(r"\bon\w+=", text, re.IGNORECASE):
        features += 1
    if re.search(r"['\"]", text):
        features += 1
    if re.search(r"\(.*\)", text):
        features += 1
    if re.search(r"javascript:|data:", text, re.IGNORECASE):
        features += 1
    if re.search(r"//|/\*", text):
        features += 1
    if re.search(r"\\[ux]", text):
        features += 1

    return min(features / 5.0, 1.0)


def _score_length(text: str) -> float:
    """prefer moderate-length payloads (50-200 chars is ideal)"""
    length = len(text)
    if length < 10:
        return 0.3
    if length <= 50:
        return 0.7
    if length <= 200:
        return 1.0
    if length <= 500:
        return 0.6
    return 0.3


def _score_technique(technique: str) -> float:
    """score based on technique type"""
    if technique in TECHNIQUE_SCORES:
        return TECHNIQUE_SCORES[technique]
    if technique.startswith("obfuscated:"):
        return 0.7
    return 0.8


def _score_char_coverage(text: str, allowed_chars: list[str]) -> float:
    """score how well the payload uses only allowed characters"""
    if not allowed_chars:
        return 1.0

    special_in_payload = set(re.findall(r"[<>'\"/\\()=;{}[\]`|&!@#$%^*~?]", text))
    if not special_in_payload:
        return 1.0

    allowed_set = set(allowed_chars)
    covered = special_in_payload & allowed_set
    ratio = len(covered) / len(special_in_payload)
    return ratio
