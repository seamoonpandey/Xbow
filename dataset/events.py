# dataset/events.py
"""
XSS-relevant HTML event handlers, grouped by category.
Used by generate_synthetic.py for payload generation.

Sources: MDN, PortSwigger XSS cheat sheet, Chrome/Safari/Firefox event references.

NOTE — parenthetical variants in the source list (e.g. onfocus(autofocus),
       ontoggle(popover)) are NOT valid attribute names on their own.
       They require an extra HTML attribute to fire and are captured
       in SPECIAL_VARIANTS at the bottom, used by extended templates.
"""

# ── Mouse ──────────────────────────────────────────────────────────────────────
MOUSE_EVENTS = [
    "onclick",
    "ondblclick",
    "onauxclick",               # middle-click / extra buttons
    "onmousedown",
    "onmouseup",
    "onmouseover",
    "onmouseout",
    "onmousemove",
    "onmouseenter",
    "onmouseleave",
    "onmousewheel",             # non-standard but widely supported
    "onwheel",
    "oncontextmenu",
]

# ── Keyboard ───────────────────────────────────────────────────────────────────
KEYBOARD_EVENTS = [
    "onkeydown",
    "onkeyup",
    "onkeypress",               # deprecated but still accepted
]

# ── Focus ──────────────────────────────────────────────────────────────────────
FOCUS_EVENTS = [
    "onfocus",
    "onblur",
    "onfocusin",
    "onfocusout",
]

# ── Form / Input ───────────────────────────────────────────────────────────────
FORM_EVENTS = [
    "oninput",
    "onchange",
    "onsubmit",
    "onreset",
    "onselect",
    "onselectionchange",
    "onselectstart",
    "oninvalid",
    "onbeforeinput",            # fires before DOM mutation
    "onsearch",                 # <input type="search">
    "onformdata",               # fires when FormData is constructed
    "onvalidationstatuschange",
]

# ── Load / Resource lifecycle ──────────────────────────────────────────────────
LOAD_EVENTS = [
    "onload",
    "onerror",
    "onabort",
    "onloadstart",
    "onloadeddata",
    "onloadedmetadata",
    "onprogress",
    "onbeforeunload",
    "onunload",
    "onunhandledrejection",
    "onresize",
    "onscroll",
    "onscrollend",              # Chrome 114+
    "onscrollsnapchange",
    "onscrollsnapchanging",
    "onhashchange",
    "onpopstate",
    "onstorage",
    "onmessage",
    "onpagehide",
    "onpageshow",
    "onpagereveal",             # Navigation API (Chrome 123+)
    "onpageswap",               # Navigation API
    "onafterprint",
    "onbeforeprint",
    "onlocation",               # non-standard; used in some frameworks
]

# ── Clipboard ──────────────────────────────────────────────────────────────────
CLIPBOARD_EVENTS = [
    "oncopy",
    "oncut",
    "onpaste",
    "onbeforecopy",
    "onbeforecut",
    "onbeforepaste",
]

# ── Drag & Drop ────────────────────────────────────────────────────────────────
DRAG_EVENTS = [
    "ondrag",
    "ondragstart",
    "ondragend",
    "ondragenter",
    "ondragleave",
    "ondragover",
    "ondragexit",               # Firefox alias for ondragleave
    "ondrop",
]

# ── Pointer (unified mouse/touch/pen) ─────────────────────────────────────────
POINTER_EVENTS = [
    "onpointerdown",
    "onpointerup",
    "onpointermove",
    "onpointerenter",
    "onpointerleave",
    "onpointerover",
    "onpointerout",
    "onpointercancel",
    "onpointerrawupdate",       # Chrome — high-frequency updates
    "ongotpointercapture",
    "onlostpointercapture",
]

# ── Touch (mobile payloads) ────────────────────────────────────────────────────
TOUCH_EVENTS = [
    "ontouchstart",
    "ontouchend",
    "ontouchmove",
    "ontouchcancel",
]

# ── Gesture (Apple / Safari) ───────────────────────────────────────────────────
GESTURE_EVENTS = [
    "ongesturestart",
    "ongesturechange",
    "ongestureend",
]

# ── Media ──────────────────────────────────────────────────────────────────────
MEDIA_EVENTS = [
    "onplay",
    "onplaying",
    "onpause",
    "onended",
    "oncancel",
    "oncanplay",
    "oncanplaythrough",
    "onvolumechange",
    "onseeking",
    "onseeked",
    "onstalled",
    "onwaiting",
    "ontimeupdate",
    "ondurationchange",
    "onratechange",
    "onemptied",
    "onsuspend",
    "oncuechange",              # <track>
]

# ── Animation & Transition ─────────────────────────────────────────────────────
ANIMATION_EVENTS = [
    "onanimationstart",
    "onanimationend",
    "onanimationiteration",
    "onanimationcancel",
    "ontransitionstart",
    "ontransitionend",
    "ontransitionrun",
    "ontransitioncancel",
]

# ── SVG / SMIL ─────────────────────────────────────────────────────────────────
SVG_EVENTS = [
    "onbegin",                  # SMIL animation begin
    "onend",                    # SMIL animation end
    "onrepeat",                 # SMIL animation repeat
    "onactivate",               # SVG activation
]

# ── Fullscreen ─────────────────────────────────────────────────────────────────
FULLSCREEN_EVENTS = [
    "onfullscreenchange",
    "onmozfullscreenchange",
    "onwebkitfullscreenchange",
]

# ── WebKit vendor-specific ─────────────────────────────────────────────────────
WEBKIT_EVENTS = [
    "onwebkitanimationend",
    "onwebkitanimationiteration",
    "onwebkitanimationstart",
    "onwebkittransitionend",
    "onwebkitmouseforcechanged",        # Apple Force Touch
    "onwebkitmouseforcedown",
    "onwebkitmouseforceup",
    "onwebkitmouseforcewillbegin",
    "onwebkitplaybacktargetavailabilitychanged",
    "onwebkitpresentationmodechanged",
    "onwebkitwillrevealbottom",
]

# ── Misc / Modern HTML5 ────────────────────────────────────────────────────────
MISC_EVENTS = [
    "ontoggle",                 # <details open ontoggle=…>
    "onbeforetoggle",           # popover / dialog (Chrome 114+)
    "onclose",                  # <dialog>
    "oncommand",                # <menu type=context>
    "onslotchange",             # <slot> in shadow DOM
    "onsecuritypolicyviolation",
    "onvisibilitychange",
    "oncontentvisibilityautostatechange",
    "onpromptaction",           # browser-level prompt callback
    "onpromptdismiss",
    "onbeforematch",            # hidden=until-found reveal (Chrome 105+)
]

# ── Aggregate export (deduped, insertion-order preserved) ──────────────────────
ALL_EVENTS: list[str] = list(dict.fromkeys(
    MOUSE_EVENTS
    + KEYBOARD_EVENTS
    + FOCUS_EVENTS
    + FORM_EVENTS
    + LOAD_EVENTS
    + CLIPBOARD_EVENTS
    + DRAG_EVENTS
    + POINTER_EVENTS
    + TOUCH_EVENTS
    + GESTURE_EVENTS
    + MEDIA_EVENTS
    + ANIMATION_EVENTS
    + SVG_EVENTS
    + FULLSCREEN_EVENTS
    + WEBKIT_EVENTS
    + MISC_EVENTS
))

# ── Special variants that require an extra HTML attribute to fire ──────────────
# Format: { event_name: extra_attribute_string }
# Used by extended templates in generate_synthetic.py
SPECIAL_VARIANTS: dict[str, str] = {
    "onfocus":    "autofocus",                              # onfocus(autofocus)
    "ontoggle":   "open",                                   # ontoggle(popover)
    "onwaiting":  "loop",                                   # onwaiting(loop)
    "oncontentvisibilityautostatechange": "style=\"content-visibility:auto\"",
}

# ── High-value subset — used as default in generate_synthetic.py ───────────────
# Criteria: fires without (or with minimal) user interaction, wide browser support
HIGH_VALUE_EVENTS: list[str] = [
    # ─ fire automatically on load / resource events ─
    "onload",
    "onerror",
    "onbegin",
    "onend",
    "onrepeat",
    "onanimationend",
    "onanimationstart",
    "onanimationiteration",
    "onanimationcancel",
    "ontransitionend",
    "ontransitionstart",
    "ontransitionrun",
    "onwebkitanimationend",
    "onwebkittransitionend",
    # ─ toggle / dialog / popover ─
    "ontoggle",
    "onbeforetoggle",
    "onclose",
    "onbeforematch",
    # ─ mouse interaction ─
    "onclick",
    "ondblclick",
    "onauxclick",
    "onmouseover",
    "onmouseenter",
    "onmousedown",
    "onmouseup",
    "oncontextmenu",
    "onwheel",
    "onmousewheel",
    # ─ focus (especially with autofocus) ─
    "onfocus",
    "onblur",
    "onfocusin",
    "onfocusout",
    # ─ keyboard ─
    "onkeydown",
    "onkeyup",
    "onkeypress",
    # ─ pointer ─
    "onpointerdown",
    "onpointerup",
    "onpointermove",
    "onpointerover",
    "onpointercancel",
    "onpointerrawupdate",
    "ongotpointercapture",
    # ─ touch / gesture ─
    "ontouchstart",
    "ontouchend",
    "ontouchmove",
    "ongestureend",
    "ongesturestart",
    # ─ clipboard / stored XSS ─
    "oncopy",
    "oncut",
    "onpaste",
    "onbeforecopy",
    "onbeforecut",
    "onbeforepaste",
    # ─ drag ─
    "ondragover",
    "ondrop",
    "ondragstart",
    "ondragenter",
    # ─ form / input ─
    "oninput",
    "oninvalid",
    "onbeforeinput",
    "onchange",
    "onsubmit",
    "onreset",
    "onselect",
    "onsearch",
    # ─ media ─
    "onplay",
    "onplaying",
    "onpause",
    "onended",
    "oncanplay",
    "onwaiting",
    "onstalled",
    "onvolumechange",
    # ─ fullscreen ─
    "onfullscreenchange",
    "onmozfullscreenchange",
    "onwebkitfullscreenchange",
    # ─ page lifecycle ─
    "onpageshow",
    "onpagehide",
    "onpagereveal",
    "onpageswap",
    "onscrollend",
    "onscrollsnapchange",
    "onhashchange",
    "onpopstate",
    # ─ security / misc ─
    "onsecuritypolicyviolation",
    "onpromptaction",
    "onpromptdismiss",
]

if __name__ == "__main__":
    print(f"Total events       : {len(ALL_EVENTS)}")
    print(f"High-value events  : {len(HIGH_VALUE_EVENTS)}")
    print(f"Special variants   : {len(SPECIAL_VARIANTS)}")
    dupes = len(ALL_EVENTS) - len(set(ALL_EVENTS))
    hv_dupes = len(HIGH_VALUE_EVENTS) - len(set(HIGH_VALUE_EVENTS))
    print(f"Duplicates (total) : {dupes}")
    print(f"Duplicates (HV)    : {hv_dupes}")
