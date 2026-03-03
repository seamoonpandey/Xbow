"""
collect_portswigger — scrapes PortSwigger XSS Cheat Sheet and normalizes
payloads into the project's CSV format for integration with the payload bank.

Source: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

Output: dataset/processed/portswigger_payloads.csv
        with columns: payload, context, technique, severity, length, source
"""

import csv
import logging
import re
import sys
from pathlib import Path

from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("collect_portswigger")

# ── category → context mapping ──────────────────────────────────────

SECTION_TO_CONTEXT = {
    # event handlers
    "event handlers that do not require user interaction": "event_handler",
    "event handlers that do require user interaction": "event_handler",
    "event handlers": "event_handler",
    # tags & injection
    "consuming tags": "tag_injection",
    "special tags": "tag_injection",
    "other useful attributes": "tag_injection",
    # script
    "js hoisting": "script_injection",
    # encodings & obfuscation
    "encoding": "attribute_escape",
    "obfuscation": "attribute_escape",
    # template injection
    "client-side template injection": "template_injection",
    "vuejs reflected": "template_injection",
    "angularjs sandbox escapes reflected": "template_injection",
    "dom based angularjs sandbox escapes": "template_injection",
    "angularjs csp bypasses": "template_injection",
    # protocols
    "protocols": "js_uri",
    # frameworks
    "frameworks": "tag_injection",
    # file upload
    "file upload attacks": "tag_injection",
    # restricted chars
    "restricted characters": "attribute_escape",
    # scriptless
    "scriptless attacks": "tag_injection",
    "dangling markup": "tag_injection",
    # content types
    "content types": "tag_injection",
    # waf bypass
    "waf bypass global objects": "attribute_escape",
}

# ── technique classification ────────────────────────────────────────

def classify_technique(payload: str, section: str) -> str:
    """Classify technique based on payload characteristics and section."""
    pl = payload.lower()
    sl = section.lower()

    if "encoding" in sl:
        return "encoding"
    if "obfuscation" in sl:
        return "obfuscation"
    if "template" in sl or "angular" in sl or "vue" in sl:
        return "template"
    if "restricted" in sl:
        return "restricted_chars"

    # check payload patterns
    if "\\u" in pl or "\\x" in pl or "&#" in pl:
        return "encoding"
    if "/*" in pl or "//" in pl or "concat" in pl:
        return "obfuscation"
    if "{{" in pl or "${" in pl or "ng-" in pl:
        return "template"
    if re.search(r"on\w+=", pl, re.IGNORECASE):
        return "event_handler"
    if "<script" in pl:
        return "script_tag"
    if "javascript:" in pl or "data:" in pl:
        return "protocol"
    if "<" in pl:
        return "tag_injection"

    return "none"


# ── severity classification ─────────────────────────────────────────

def classify_severity(payload: str, context: str, technique: str) -> str:
    """Classify severity based on auto-trigger potential."""
    pl = payload.lower()

    # auto-triggering = high
    auto_triggers = [
        "onerror=", "onload=", "<script", "onanimation", "onbegin=",
        "onfocus=", "autofocus", "ontoggle=", "onpointerenter=",
    ]
    if any(t in pl for t in auto_triggers):
        return "high"

    # requires user interaction = medium
    interaction_triggers = [
        "onclick=", "onmouseover=", "onmouseenter=", "oncontextmenu=",
        "ondblclick=", "onkeydown=", "onkeyup=", "oninput=",
    ]
    if any(t in pl for t in interaction_triggers):
        return "medium"

    # template injection / protocol = medium
    if context in ("template_injection", "js_uri"):
        return "medium"

    # scriptless/markup = low
    if "scriptless" in technique or context == "tag_injection":
        return "low"

    return "medium"


# ── main extraction ─────────────────────────────────────────────────

def extract_payloads(html_path: str) -> list[dict]:
    """Extract and categorize payloads from PortSwigger HTML."""
    with open(html_path, "r", encoding="utf-8") as f:
        soup = BeautifulSoup(f.read(), "html.parser")

    code_blocks = soup.find_all("code")
    logger.info(f"Found {len(code_blocks)} code blocks")

    payloads = []
    seen = set()

    for cb in code_blocks:
        text = cb.get_text().strip()
        if not text or len(text) < 5:
            continue

        # deduplicate
        if text in seen:
            continue
        seen.add(text)

        # find section header
        section = "generic"
        node = cb
        prev = node.find_previous(["h2", "h3"])
        if prev:
            section = prev.get_text().strip()

        # map to context
        context = SECTION_TO_CONTEXT.get(section.lower(), "generic")

        # refine context based on payload content
        context = _refine_context(text, context)

        # classify technique
        technique = classify_technique(text, section)

        # classify severity
        severity = classify_severity(text, context, technique)

        payloads.append({
            "payload": text,
            "context": context,
            "technique": technique,
            "severity": severity,
            "length": len(text),
            "source": "portswigger",
        })

    logger.info(f"Extracted {len(payloads)} unique payloads")
    return payloads


def _refine_context(payload: str, default_context: str) -> str:
    """Refine context based on actual payload content."""
    pl = payload.lower()

    # template injection patterns
    if "{{" in pl or "${" in pl or "ng-" in pl or "v-" in pl:
        return "template_injection"

    # javascript: or data: URI
    if pl.startswith("javascript:") or pl.startswith("data:"):
        return "js_uri"

    # DOM sink patterns
    if any(s in pl for s in ["document.write", ".innerhtml", "eval(", "setinterval(", "settimeout("]):
        return "dom_sink"

    # script tag injection
    if "<script" in pl and "</script" in pl:
        return "script_injection"

    # event handler with attribute context
    if re.search(r'["\'][^"\']*on\w+=', pl):
        return "attribute"

    # pure event handler tag
    if re.search(r"<\w+[^>]+on\w+=", pl, re.IGNORECASE):
        return "event_handler"

    return default_context


def write_csv(payloads: list[dict], output_path: str):
    """Write payloads to CSV."""
    fieldnames = ["payload", "context", "technique", "severity", "length", "source"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(payloads)
    logger.info(f"Written {len(payloads)} payloads to {output_path}")


def print_stats(payloads: list[dict]):
    """Print distribution stats."""
    from collections import Counter

    ctx_dist = Counter(p["context"] for p in payloads)
    tech_dist = Counter(p["technique"] for p in payloads)
    sev_dist = Counter(p["severity"] for p in payloads)

    logger.info("Context distribution:")
    for ctx, count in ctx_dist.most_common():
        logger.info(f"  {ctx}: {count}")

    logger.info("Technique distribution:")
    for tech, count in tech_dist.most_common():
        logger.info(f"  {tech}: {count}")

    logger.info("Severity distribution:")
    for sev, count in sev_dist.most_common():
        logger.info(f"  {sev}: {count}")


def main():
    html_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/portswigger_raw.html"
    output_dir = Path(__file__).resolve().parent.parent / "dataset" / "processed"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "portswigger_payloads.csv"

    if not Path(html_path).exists():
        logger.error(f"HTML file not found: {html_path}")
        logger.info("Download with: curl -sL https://portswigger.net/web-security/cross-site-scripting/cheat-sheet -o /tmp/portswigger_raw.html")
        sys.exit(1)

    payloads = extract_payloads(html_path)
    print_stats(payloads)
    write_csv(payloads, str(output_path))


if __name__ == "__main__":
    main()
