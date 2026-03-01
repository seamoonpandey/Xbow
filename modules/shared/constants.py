"""
shared constants across python microservices
"""

CONTEXT_TYPES = [
    "html_body",
    "attribute",
    "js_string",
    "js_block",
    "url",
    "none",
]

AI_CONTEXT_LABELS = [
    "script_injection",
    "event_handler",
    "js_uri",
    "tag_injection",
    "template_injection",
    "dom_sink",
    "attribute_escape",
    "generic",
]

SEVERITY_LABELS = [
    "low",
    "medium",
    "high",
]

# mapping from ai classifier labels to context types
AI_TO_CONTEXT_MAP = {
    "script_injection": "js_block",
    "event_handler": "attribute",
    "js_uri": "url",
    "tag_injection": "html_body",
    "template_injection": "js_block",
    "dom_sink": "js_block",
    "attribute_escape": "attribute",
    "generic": "html_body",
}

SPECIAL_CHARS = ["<", ">", '"', "'", "/", "\\", "(", ")", "{", "}", ";", "=", "`"]

PROBE_MARKER_PREFIX = "rs0x"
