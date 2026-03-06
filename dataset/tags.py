# dataset/tags.py
"""
XSS-relevant HTML tags, grouped by injection surface.
Used by generate_synthetic.py for payload generation.

Sources: PortSwigger XSS cheat sheet, MDN, HTML living standard,
         browser quirks research, obsolete-tag exploit lists.

Add new tags here — generate_synthetic.py imports ALL_TAGS automatically.
"""

# ── Inline media / resource-loading (fire onerror / onload without interaction)
INLINE_MEDIA_TAGS = [
    "img",
    "image",            # SVG alias; parsed by browsers
    "svg",
    "audio",
    "video",
    "source",           # child of <video>/<audio> — src= fires onerror
    "track",            # <track onerror=…>
    "picture",
    "param",            # child of <object>
    "embed",
]

# ── Document structure ─────────────────────────────────────────────────────────
STRUCTURE_TAGS = [
    "html",
    "head",
    "body",
    "div",
    "span",
    "p",
    "section",
    "article",
    "aside",
    "header",
    "footer",
    "main",
    "nav",
    "figure",
    "figcaption",
    "address",
    "hgroup",
    "h1",
    "hr",
    "br",
    "wbr",
]

# ── Text-level / inline semantics ─────────────────────────────────────────────
TEXT_INLINE_TAGS = [
    "a",
    "abbr",
    "acronym",          # obsolete; still parsed
    "b",
    "bdi",
    "bdo",
    "big",              # obsolete; still parsed
    "blockquote",
    "cite",
    "code",
    "data",
    "dd",
    "del",
    "dfn",
    "dl",
    "dt",
    "em",
    "i",
    "ins",
    "kbd",
    "li",
    "mark",
    "ol",
    "pre",
    "q",
    "rb",
    "rp",
    "rt",
    "rtc",
    "ruby",
    "s",
    "samp",
    "small",
    "strike",           # obsolete; still parsed
    "strong",
    "sub",
    "sup",
    "time",
    "tt",               # obsolete; still parsed
    "u",
    "ul",
    "var",
]

# ── Embedding / framing / navigation ──────────────────────────────────────────
EMBED_TAGS = [
    "iframe",
    "object",
    "applet",           # obsolete; accepted by some parsers
    "frame",
    "frameset",
    "portal",           # Chrome experimental
]

# ── Interactive / form ─────────────────────────────────────────────────────────
FORM_TAGS = [
    "input",
    "button",
    "textarea",
    "select",
    "form",
    "label",
    "legend",
    "fieldset",
    "output",
    "meter",
    "progress",
    "datalist",
    "optgroup",
    "option",
    "keygen",           # deprecated; still parsed in Blink/WebKit
    "map",
    "area",
]

# ── URL-bearing / injection via href/src/content ──────────────────────────────
URL_TAGS = [
    "base",             # <base href="javascript:…">
    "link",             # <link rel=stylesheet href="javascript:…">
    "meta",             # <meta http-equiv="refresh" content="0;url=javascript:…">
]

# ── Scripting / style / raw-text ──────────────────────────────────────────────
SCRIPT_STYLE_TAGS = [
    "script",
    "style",
    "noscript",
    "noembed",
    "noframes",
    "template",         # inert by default but DOM-parseable
    "title",            # raw-text; XSS via </title><script>
    "listing",          # obsolete raw-text; behaves like <pre>
    "plaintext",        # obsolete; swallows rest of document
    "xmp",              # obsolete raw-text element
]

# ── Table family ───────────────────────────────────────────────────────────────
TABLE_TAGS = [
    "table",
    "thead",
    "tbody",
    "tfoot",
    "tr",
    "td",
    "th",
    "caption",
    "colgroup",
    "col",
]

# ── Lists / menus ──────────────────────────────────────────────────────────────
LIST_TAGS = [
    "menu",
    "menuitem",         # obsolete context-menu item; Firefox
    "dir",              # obsolete list; still parsed
    "command",          # obsolete; still accepted
]

# ── Animation / effects / SVG SMIL ────────────────────────────────────────────
ANIMATION_TAGS = [
    "marquee",          # non-standard; widely exploited
    "blink",            # obsolete; Firefox/Opera
    "animate",          # SVG SMIL — <svg><animate onbegin=…>
    "set",              # SVG SMIL
    "animatetransform",
    "animatemotion",
]

# ── MathML ─────────────────────────────────────────────────────────────────────
MATH_TAGS = [
    "math",             # <math><mtext><img onerror=…>
    "mtext",
    "mi",
    "mo",
    "mn",
]

# ── Obsolete / non-standard / browser-quirk tags ──────────────────────────────
OBSOLETE_TAGS = [
    "center",           # obsolete; still parsed
    "font",             # obsolete; still parsed
    "multicol",         # Netscape; still tokenised by Gecko
    "nextid",           # NCSA Mosaic relic; some parsers accept it
    "nobr",             # non-standard no-break
    "spacer",           # Netscape; still tokenised
    "content",          # Web Components v0 (Chrome old)
    "element",          # Web Components proposal; Chrome/Firefox
    "shadow",           # Web Components v0 shadow-dom insertion point
]

# ── Custom / catch-all ────────────────────────────────────────────────────────
CUSTOM_TAGS = [
    "details",          # <details open ontoggle=…>
    "summary",          # child of <details>
    "dialog",           # <dialog open onclose=…>
    "canvas",
    "slot",             # shadow DOM slot
    "figure",
    "time",
    "xss",              # custom tag; accepted by permissive parsers / innerHTML
]

# ── Aggregate export (deduped, insertion-order preserved) ──────────────────────
ALL_TAGS: list[str] = list(dict.fromkeys(
    INLINE_MEDIA_TAGS
    + STRUCTURE_TAGS
    + TEXT_INLINE_TAGS
    + EMBED_TAGS
    + FORM_TAGS
    + URL_TAGS
    + SCRIPT_STYLE_TAGS
    + TABLE_TAGS
    + LIST_TAGS
    + ANIMATION_TAGS
    + MATH_TAGS
    + OBSOLETE_TAGS
    + CUSTOM_TAGS
))

# ── High-value subset — used as default in generate_synthetic.py ───────────────
# Criteria: reliably fire an event handler, wide browser support
HIGH_VALUE_TAGS: list[str] = [
    # ─ fire on resource load/error — zero interaction ─
    "img", "image", "svg", "audio", "video", "source", "iframe",
    "embed", "object", "script", "body",
    # ─ form / interactive ─
    "input", "button", "textarea", "select", "form",
    # ─ toggle / dialog / popover ─
    "details", "dialog",
    # ─ layout / event targets ─
    "div", "span", "a", "p",
    # ─ animation ─
    "marquee", "animate", "set", "animatetransform", "animatemotion",
    # ─ obsolete but exploitable ─
    "blink", "marquee", "listing", "plaintext", "xmp",
    # ─ structural XSS ─
    "table", "td", "tr",
    # ─ MathML ─
    "math", "mtext",
    # ─ raw-text XSS ─
    "title", "noscript", "template",
    # ─ URL/meta injection ─
    "base", "link", "meta", "area",
    # ─ custom / permissive parsers ─
    "xss",
]
# Remove duplicates introduced by the marquee repeat above
HIGH_VALUE_TAGS = list(dict.fromkeys(HIGH_VALUE_TAGS))

if __name__ == "__main__":
    print(f"Total tags         : {len(ALL_TAGS)}")
    print(f"High-value tags    : {len(HIGH_VALUE_TAGS)}")
    dupes = len(ALL_TAGS) - len(set(ALL_TAGS))
    hv_dupes = len(HIGH_VALUE_TAGS) - len(set(HIGH_VALUE_TAGS))
    print(f"Duplicates (total) : {dupes}")
    print(f"Duplicates (HV)    : {hv_dupes}")
