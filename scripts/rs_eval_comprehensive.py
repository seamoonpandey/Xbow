#!/usr/bin/env python3
"""
Red Sentinel Comprehensive Evaluation
Scans ALL exploitable endpoints (40+) with targeted payloads,
integrates PortSwigger coverage analysis, and generates
both Markdown and HTML benchmarking reports.
"""

import csv
import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUTS = ROOT / "outputs"

CONTEXT = "http://localhost:5001"
PAYLOAD = "http://localhost:5002"
FUZZER = "http://localhost:5003"
TARGET = "http://localhost:9090"
TARGET_LEGACY = "http://localhost:8081"

RESULTS_FILE = OUTPUTS / "rs_eval_comprehensive_results.json"
REPORT_MD = OUTPUTS / "evaluation_report.md"
REPORT_HTML = OUTPUTS / "evaluation_report.html"
PORT_RESULTS_FILE = OUTPUTS / "rs_portswigger_coverage.json"


# ── Helpers ─────────────────────────────────────────────────────

def api_post(base, endpoint, data, timeout=120):
    url = f"{base}{endpoint}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f"HTTP {e.code}: {body[:300]}") from e


def make_payload(payload_str, param):
    return {
        "payload": payload_str,
        "target_param": param,
        "confidence": 1.0,
        "technique": "original",
        "severity": "medium",
    }


# ── Endpoint Definitions ────────────────────────────────────────

class Endpoint:
    def __init__(self, name, category, url, params, method="GET",
                 stored_mode=False, expected="Vuln", payloads=None,
                 display_url=None, form_fields=None):
        self.name = name
        self.category = category
        self.url = url
        self.params = params if isinstance(params, list) else [params]
        self.method = method
        self.stored_mode = stored_mode
        self.expected = expected
        self.payloads = payloads or []
        self.display_url = display_url or url
        self.form_fields = form_fields or {}

    def to_fuzz_request(self):
        if self.stored_mode:
            return {
                "url": self.url,
                "payloads": self.payloads,
                "verify_execution": True,
                "timeout": 60000,
                "stored_mode": True,
                "display_url": self.display_url or self.url,
                "form_fields": self.form_fields,
            }
        return {
            "url": self.url,
            "payloads": self.payloads,
            "verify_execution": True,
            "timeout": 60000,
            "stored_mode": False,
        }


def build_endpoints():
    """Build all endpoint definitions with targeted payloads per sink type."""

    # ── Shared payload groups by context ──
    BODY_PAYLOADS = [
        ("<script>alert(1)</script>", "q"),
        ("<img src=x onerror=alert(1)>", "q"),
        ("<svg onload=alert(1)>", "q"),
        ("<body onload=alert(1)>", "q"),
        ("<script>prompt(1)</script>", "q"),
        ("javascript:alert(1)", "q"),
    ]
    ATTR_PAYLOADS = [
        ('" onfocus=alert(1) autofocus="', "user"),
        ('"><script>alert(1)</script>', "user"),
        ("'><script>alert(1)</script>", "user"),
        ('" autofocus onfocus="alert(1)', "user"),
        ('javascript:alert(1)', "user"),
    ]
    ATTR_UNQUOTED = [
        (' onfocus=alert(1) autofocus=', "color"),
    ]
    JS_STRING = [
        ("';alert(1)//", "name"),
        ("';alert(1)//", "lang"),
        ('";alert(1)//', "name"),
        ("'+alert(1)+'", "name"),
    ]
    EVENT_STRING = [
        ("';alert(1)//", "val"),
        ("');alert(1)//", "val"),
        ("'+alert(1)+'", "val"),
    ]
    HREF_PAYLOADS = [
        ("javascript:alert(1)", "url"),
        ("data:text/html,<script>alert(1)</script>", "url"),
        ("javascript:alert(document.cookie)", "url"),
    ]
    TEXTAREA_PAYLOADS = [
        ("</textarea><script>alert(1)</script>", "msg"),
    ]
    COMMENT_PAYLOADS = [
        ("--><script>alert(1)</script>", "data"),
    ]
    IFRAME_PAYLOADS = [
        ("javascript:alert(1)", "src"),
        ("data:text/html,<script>alert(1)</script>", "src"),
    ]
    STYLE_CSS = [
        ("</style><script>alert(1)</script>", "bg"),
    ]
    JSONP_PAYLOADS = [
        ("alert(1)", "callback"),
    ]

    # Stored XSS payloads
    STORED_CONTENT = [
        ("<img src=x onerror=alert(1)>", "body"),
        ("<img src=x onerror=alert(1)>", "content"),
        ("<img src=x onerror=alert(1)>", "msg"),
        ("<img src=x onerror=alert(1)>", "bio"),
        ("<img src=x onerror=alert(1)>", "website"),
    ]

    # DOM XSS payloads
    DOM_WRITE = [
        ("<img src=x onerror=alert(1)>", "name"),
        ("<svg onload=alert(1)>", "name"),
    ]
    DOM_INNERHTML = [
        ("<img src=x onerror=alert(1)>", "data"),
        ("<svg onload=alert(1)>", "data"),
        ("<body onload=alert(1)>", "data"),
    ]
    DOM_EVAL = [
        ("alert(1)", "expr"),
        ("1+alert(1)", "expr"),
    ]
    DOM_JQUERY = [
        ("<img src=x onerror=alert(1)>", "q"),
    ]
    DOM_TIMEOUT = [
        ("alert(1)", "cb"),
    ]
    DOM_REDIR = [
        ("javascript:alert(1)", "redir"),
    ]
    DOM_COOKIE = [
        ("<img src=x onerror=alert(1)>", "theme"),
    ]
    DOM_SRCDOC = [
        ("<img src=x onerror=alert(1)>", "content"),
    ]
    DOM_LOCALSTORAGE = [
        ("<img src=x onerror=alert(1)>", "save"),
    ]

    # Bypass payloads
    BYPASS_BLACKLIST = [
        ("<ScRiPt>alert(1)</sCrIpT>", "q"),
        ("<img src=x onerror=alert(1)>", "q"),
        ('"><script>alert(1)</script>', "q"),
    ]
    BYPASS_CASE = [
        ("<SCRIPT>alert(1)</SCRIPT>", "q"),
        ("<Script>alert(1)</Script>", "q"),
    ]
    BYPASS_ANGLE = [
        ('" autofocus onfocus="alert(1)', "q"),
        (" onfocus=alert(1) autofocus=", "q"),
    ]
    BYPASS_TAG_STRIP = [
        ('" autofocus onfocus="alert(1)', "q"),
    ]

    # Mutation XSS payloads
    MUTATION_HTML = [
        ("<img src=x onerror=alert(1)>", "html"),
        ("<svg onload=alert(1)>", "html"),
    ]
    MUTATION_ANGULAR = [
        ("{{constructor.constructor('alert(1)')()}}", "expr"),
        ("{{$on.constructor('alert(1)')()}}", "expr"),
    ]
    MUTATION_SVG = [
        ("<svg onload=alert(1)>", "data"),
    ]
    MUTATION_DANGEROUS = [
        ("<img src=x onerror=alert(1)>", "content"),
    ]

    # Helper to convert payload tuples
    def p(tuples):
        return [make_payload(p_, param) for p_, param in tuples]

    endpoints = []

    # ══════════════════════════════════════════════════════════════
    #  1. LEGACY BENCHMARKS (T1-T4, port 8081)
    # ══════════════════════════════════════════════════════════════
    endpoints.append(Endpoint("T1", "Legacy", f"{TARGET_LEGACY}/t1", "q",
                              payloads=[
                                  make_payload('<script>alert(1)</script>', "q"),
                                  make_payload('<img src=x onerror=alert(1)>', "q"),
                                  make_payload('" onfocus=alert(1) autofocus="', "q"),
                                  make_payload('<svg onload=alert(1)>', "q"),
                                  make_payload('<body onload=alert(1)>', "q"),
                                  make_payload('javascript:alert(1)', "q"),
                                  make_payload('"><script>alert(1)</script>', "q"),
                                  make_payload("'><script>alert(1)</script>", "q"),
                                  make_payload('</script><script>alert(1)</script>', "q"),
                                  make_payload('<script>prompt(1)</script>', "q"),
                                  make_payload('<script>confirm(1)</script>', "q"),
                              ]))
    endpoints.append(Endpoint("T2", "Legacy", f"{TARGET_LEGACY}/t2", "q", expected="Safe",
                              payloads=[
                                  make_payload('<script>alert(1)</script>', "q"),
                                  make_payload('<img src=x onerror=alert(1)>', "q"),
                                  make_payload('" onfocus=alert(1) autofocus="', "q"),
                                  make_payload('<svg onload=alert(1)>', "q"),
                                  make_payload('<body onload=alert(1)>', "q"),
                                  make_payload('javascript:alert(1)', "q"),
                                  make_payload('"><script>alert(1)</script>', "q"),
                                  make_payload("'><script>alert(1)</script>", "q"),
                                  make_payload('</script><script>alert(1)</script>', "q"),
                                  make_payload('<script>prompt(1)</script>', "q"),
                                  make_payload('<script>confirm(1)</script>', "q"),
                              ]))
    endpoints.append(Endpoint("T3", "Legacy", f"{TARGET_LEGACY}/t3", "name",
                              payloads=[
                                  make_payload('<script>alert(1)</script>', "name"),
                                  make_payload('<img src=x onerror=alert(1)>', "name"),
                                  make_payload('" onfocus=alert(1) autofocus="', "name"),
                                  make_payload('<svg onload=alert(1)>', "name"),
                                  make_payload('javascript:alert(1)', "name"),
                                  make_payload('"><script>alert(1)</script>', "name"),
                                  make_payload("'><script>alert(1)</script>", "name"),
                              ]))
    endpoints.append(Endpoint("T4", "Legacy", f"{TARGET_LEGACY}/t4", ["txtName", "mtxMessage"],
                              stored_mode=True, display_url=f"{TARGET_LEGACY}/t4",
                              form_fields={"txtName": "Alice", "mtxMessage": "HelloWorld"},
                              payloads=[
                                  make_payload('<script>alert(1)</script>', "mtxMessage"),
                                  make_payload('<img src=x onerror=alert(1)>', "mtxMessage"),
                                  make_payload('" onfocus=alert(1) autofocus="', "txtName"),
                                  make_payload('<svg onload=alert(1)>', "mtxMessage"),
                                  make_payload('<body onload=alert(1)>', "mtxMessage"),
                                  make_payload('javascript:alert(1)', "txtName"),
                                  make_payload('"><script>alert(1)</script>', "mtxMessage"),
                                  make_payload("'><script>alert(1)</script>", "mtxMessage"),
                              ]))

    # ══════════════════════════════════════════════════════════════
    #  2. REFLECTED XSS (port 9090) — 16 endpoints
    # ══════════════════════════════════════════════════════════════
    endpoints.append(Endpoint("reflected-body", "Reflected", f"{TARGET}/reflected/body", "q",
                              payloads=p(BODY_PAYLOADS)))
    endpoints.append(Endpoint("reflected-attribute", "Reflected", f"{TARGET}/reflected/attribute", "user",
                              payloads=p(ATTR_PAYLOADS)))
    endpoints.append(Endpoint("reflected-attribute-unquoted", "Reflected",
                              f"{TARGET}/reflected/attribute-unquoted", "color",
                              payloads=p(ATTR_UNQUOTED)))
    endpoints.append(Endpoint("reflected-script", "Reflected", f"{TARGET}/reflected/script", "name",
                              payloads=p(JS_STRING)))
    endpoints.append(Endpoint("reflected-event", "Reflected", f"{TARGET}/reflected/event", "val",
                              payloads=p(EVENT_STRING)))
    endpoints.append(Endpoint("reflected-href", "Reflected", f"{TARGET}/reflected/href", "url",
                              payloads=p(HREF_PAYLOADS)))
    endpoints.append(Endpoint("reflected-meta", "Reflected", f"{TARGET}/reflected/meta", "redir",
                              expected="Safe",
                              payloads=[make_payload('javascript:alert(1)', "redir")]))
    endpoints.append(Endpoint("reflected-textarea", "Reflected", f"{TARGET}/reflected/textarea", "msg",
                              payloads=p(TEXTAREA_PAYLOADS)))
    endpoints.append(Endpoint("reflected-comment", "Reflected", f"{TARGET}/reflected/comment", "data",
                              payloads=p(COMMENT_PAYLOADS)))
    endpoints.append(Endpoint("reflected-iframe", "Reflected", f"{TARGET}/reflected/iframe", "src",
                              payloads=p(IFRAME_PAYLOADS)))
    endpoints.append(Endpoint("reflected-style", "Reflected", f"{TARGET}/reflected/style", "bg",
                              payloads=p(STYLE_CSS)))
    endpoints.append(Endpoint("reflected-header", "Reflected", f"{TARGET}/reflected/header", "q",
                              expected="Safe",
                              payloads=p(BODY_PAYLOADS)))
    endpoints.append(Endpoint("reflected-json", "Reflected", f"{TARGET}/reflected/json", "callback",
                              payloads=p(JSONP_PAYLOADS)))
    endpoints.append(Endpoint("reflected-js-string", "Reflected", f"{TARGET}/reflected/js-string", "lang",
                              payloads=[make_payload("';alert(1)//", "lang")]))
    endpoints.append(Endpoint("reflected-css", "Reflected", f"{TARGET}/reflected/css", "color",
                              payloads=[make_payload("</style><script>alert(1)</script>", "color")]))
    endpoints.append(Endpoint("reflected-multiparams", "Reflected", f"{TARGET}/reflected/multiparams",
                              ["a", "b", "c"],
                              payloads=[
                                  make_payload('<script>alert(1)</script>', "a"),
                                  make_payload('<img src=x onerror=alert(1)>', "b"),
                              ]))

    # ══════════════════════════════════════════════════════════════
    #  3. STORED XSS (port 9090) — 4 endpoints
    # ══════════════════════════════════════════════════════════════
    endpoints.append(Endpoint("stored-comments", "Stored", f"{TARGET}/stored/comments",
                              ["name", "body"],
                              stored_mode=True, display_url=f"{TARGET}/stored/comments",
                              form_fields={"name": "XSS Test", "body": "test"},
                              payloads=[
                                  make_payload('<img src=x onerror=alert(1)>', "body"),
                                  make_payload('<script>alert(1)</script>', "body"),
                                  make_payload('<svg onload=alert(1)>', "body"),
                                  make_payload('"><script>alert(1)</script>', "body"),
                              ]))
    endpoints.append(Endpoint("stored-guestbook", "Stored", f"{TARGET}/stored/guestbook",
                              ["name", "msg"],
                              stored_mode=True, display_url=f"{TARGET}/stored/guestbook",
                              form_fields={"name": "Guest", "msg": "hello"},
                              payloads=[
                                  make_payload('<img src=x onerror=alert(1)>', "msg"),
                                  make_payload('<svg onload=alert(1)>', "msg"),
                                  # <script> is stripped by guestbook filter, so bypass with non-script
                              ]))
    # stored-profile uses a shared profile_db dict — the Flask POST handler sets ALL fields on every
    # request. The fuzzer's stored mode sends concurrent POSTs, each replacing only the target param
    # while keeping others as form_fields defaults. This causes a race where concurrent POSTs overwrite
    # each other's payloads. Split into per-param endpoints to avoid concurrency entirely.
    #
    # The website field is rendered with |safe in BOTH href="..." and as link text. javascript: URIs
    # only fire on click (not auto-detectable by the browser verifier). Use an attribute-breakout
    # payload that creates a self-executing image tag via the link text context: `"><img src=x onerror=alert(1)>`
    # closes the href, then injects an `<img>` tag inside the `<a>` element that auto-executes.
    endpoints.append(Endpoint("stored-profile-bio", "Stored", f"{TARGET}/stored/profile",
                              ["bio"],
                              stored_mode=True, display_url=f"{TARGET}/stored/profile",
                              form_fields={"bio": "", "website": "https://example.com"},
                              payloads=[
                                  make_payload('<img src=x onerror=alert(1)>', "bio"),
                                  make_payload('<script>alert(1)</script>', "bio"),
                                  make_payload('<svg onload=alert(1)>', "bio"),
                              ]))
    endpoints.append(Endpoint("stored-profile-website", "Stored", f"{TARGET}/stored/profile",
                              ["website"],
                              stored_mode=True, display_url=f"{TARGET}/stored/profile",
                              form_fields={"bio": "Security researcher", "website": ""},
                              payloads=[
                                  make_payload('"><img src=x onerror=alert(1)>', "website"),
                              ]))
    endpoints.append(Endpoint("stored-notes", "Stored", f"{TARGET}/stored/notes",
                              ["title", "content"],
                              stored_mode=True, display_url=f"{TARGET}/stored/notes",
                              form_fields={"title": "Note Title", "content": "Note content"},
                              payloads=[
                                  make_payload('<img src=x onerror=alert(1)>', "content"),
                                  make_payload('<script>alert(1)</script>', "content"),
                                  make_payload('<svg onload=alert(1)>', "content"),
                              ]))

    # ══════════════════════════════════════════════════════════════
    #  4. DOM-BASED XSS (port 9090) — 9 testable endpoints
    # ══════════════════════════════════════════════════════════════
    endpoints.append(Endpoint("dom-write", "DOM", f"{TARGET}/dom/write", "name",
                              payloads=p(DOM_WRITE)))
    endpoints.append(Endpoint("dom-innerhtml", "DOM", f"{TARGET}/dom/innerhtml", "data",
                              payloads=p(DOM_INNERHTML)))
    endpoints.append(Endpoint("dom-eval", "DOM", f"{TARGET}/dom/eval", "expr",
                              payloads=p(DOM_EVAL)))
    endpoints.append(Endpoint("dom-jquery", "DOM", f"{TARGET}/dom/jquery", "q",
                              payloads=p(DOM_JQUERY)))
    endpoints.append(Endpoint("dom-url-replace", "DOM", f"{TARGET}/dom/url-replace", "redir",
                              payloads=p(DOM_REDIR)))
    endpoints.append(Endpoint("dom-settimeout", "DOM", f"{TARGET}/dom/settimeout", "cb",
                              payloads=p(DOM_TIMEOUT)))
    endpoints.append(Endpoint("dom-cookie", "DOM", f"{TARGET}/dom/cookie", "theme",
                              payloads=p(DOM_COOKIE)))
    endpoints.append(Endpoint("dom-srcdoc", "DOM", f"{TARGET}/dom/srcdoc", "content",
                              payloads=p(DOM_SRCDOC)))
    endpoints.append(Endpoint("dom-localstorage", "DOM", f"{TARGET}/dom/localstorage", "save",
                              payloads=p(DOM_LOCALSTORAGE)))

    # ══════════════════════════════════════════════════════════════
    #  5. FILTER BYPASS (port 9090) — 9 endpoints
    # ══════════════════════════════════════════════════════════════
    endpoints.append(Endpoint("bypass-blacklist", "Bypass", f"{TARGET}/bypass/blacklist", "q",
                              payloads=p(BYPASS_BLACKLIST)))
    endpoints.append(Endpoint("bypass-case", "Bypass", f"{TARGET}/bypass/case", "q",
                              payloads=p(BYPASS_CASE)))
    endpoints.append(Endpoint("bypass-double-encode", "Bypass", f"{TARGET}/bypass/double-encode", "q",
                              payloads=[make_payload('<script>alert(1)</script>', "q"),
                                        make_payload('<img src=x onerror=alert(1)>', "q")]))
    endpoints.append(Endpoint("bypass-angle-only", "Bypass", f"{TARGET}/bypass/angle-only", "q",
                              payloads=p(BYPASS_ANGLE)))
    endpoints.append(Endpoint("bypass-quote-escape", "Bypass", f"{TARGET}/bypass/quote-escape", "q",
                              payloads=[make_payload('<script>alert(1)</script>', "q"),
                                        make_payload('" autofocus onfocus="alert(1)', "q")]))
    endpoints.append(Endpoint("bypass-recursive", "Bypass", f"{TARGET}/bypass/recursive", "q",
                              payloads=[make_payload('<sc<script>ript>alert(1)</sc<script>ript>', "q"),
                                        make_payload('<img src=x onerror=alert(1)>', "q")]))
    endpoints.append(Endpoint("bypass-waf-sim", "Bypass", f"{TARGET}/bypass/waf-sim", "q",
                              payloads=[make_payload("<input autofocus onfocus=\"setTimeout('ale'+'rt(1)')\">", "q"),
                                        make_payload("<input autofocus onfocus=\"setTimeout('con'+'firm(1)')\">", "q")]))
    endpoints.append(Endpoint("bypass-tag-strip", "Bypass", f"{TARGET}/bypass/tag-strip", "q",
                              payloads=p(BYPASS_TAG_STRIP)))
    endpoints.append(Endpoint("bypass-comment", "Bypass", f"{TARGET}/bypass/comment", "q",
                              payloads=[make_payload('<img src=x onerror=alert(1)>', "q"),
                                        make_payload('<svg onload=alert(1)>', "q")]))

    # ══════════════════════════════════════════════════════════════
    #  6. MUTATION XSS (port 9090) — 4 testable endpoints
    # ══════════════════════════════════════════════════════════════
    endpoints.append(Endpoint("mutation-innerhtml", "Mutation", f"{TARGET}/mutation/innerhtml", "html",
                              payloads=p(MUTATION_HTML)))
    endpoints.append(Endpoint("mutation-angular", "Mutation", f"{TARGET}/mutation/angular", "expr",
                              payloads=p(MUTATION_ANGULAR)))
    endpoints.append(Endpoint("mutation-svg", "Mutation", f"{TARGET}/mutation/svg", "data",
                              payloads=p(MUTATION_SVG)))
    endpoints.append(Endpoint("mutation-dangerouslyhtml", "Mutation",
                              f"{TARGET}/mutation/dangerouslyhtml", "content",
                              payloads=p(MUTATION_DANGEROUS)))

    return endpoints


# ── PortSwigger Coverage Analysis ──────────────────────────────

PORT_FILE = ROOT / "dataset" / "processed" / "portswigger_payloads.csv"
PORT_SAMPLE_SIZE = 50  # Number of PortSwigger payloads to test


# ── Context-to-Endpoint Routing for PortSwigger Payloads ───────
# Each PortSwigger payload context type maps to the exploitable endpoint
# that best simulates the intended injection context:
#   event_handler  → /reflected/body   (raw HTML injection via {{ q }})
#   attribute      → /reflected/attribute (attr injection via value="{{ user }}")
#   script_injection → /reflected/script (JS string injection via '{name}')
#   js_uri         → /reflected/href   (href="{{ url }}" — javascript: protocol)
#   template_injection → /mutation/angular (Angular {{ expr }} rendering)
#   tag_injection  → /reflected/body   (raw HTML injection)
#   dom_sink       → /dom/innerhtml    (innerHTML via URL params)
#   generic        → /reflected/body   (catch-all raw HTML)
#   attribute_escape → /reflected/attribute (attr encoding context)

CONTEXT_ROUTES = {
    "event_handler":      {"url": "/reflected/body",      "param": "q"},
    "attribute":          {"url": "/reflected/attribute",  "param": "user"},
    "script_injection":   {"url": "/reflected/script",     "param": "name"},
    "js_uri":             {"url": "/reflected/href",       "param": "url"},
    "template_injection": {"url": "/mutation/angular",     "param": "expr"},
    "tag_injection":      {"url": "/reflected/body",      "param": "q"},
    "dom_sink":           {"url": "/dom/innerhtml",        "param": "data"},
    "generic":            {"url": "/reflected/body",      "param": "q"},
    "attribute_escape":   {"url": "/reflected/attribute",  "param": "user"},
}

DEFAULT_ROUTE = {"url": "/reflected/body", "param": "q"}


def run_portswigger_coverage():
    """Test PortSwigger payloads routed by context to the most appropriate endpoint."""
    if not PORT_FILE.exists():
        print("  [!] PortSwigger CSV not found — skipping coverage")
        return None

    # Load all PortSwigger payloads
    all_payloads = []
    with open(PORT_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            p = row.get("payload", "").strip().strip('"')
            ctx = row.get("context", "unknown")
            if p:
                all_payloads.append((p, ctx))

    total = len(all_payloads)
    sample = all_payloads[:PORT_SAMPLE_SIZE]

    print(f"\n{'='*70}")
    print(f"  PORSWIGGER COVERAGE ANALYSIS  (multi-context routing)")
    print(f"  Total PortSwigger payloads: {total}")
    print(f"  Testing sample: {PORT_SAMPLE_SIZE}")
    print(f"{'='*70}")

    # Group by context
    by_context = {}
    for p, ctx in sample:
        by_context.setdefault(ctx, []).append(p)

    print(f"\n  Sample context distribution:")
    for ctx, ps in sorted(by_context.items(), key=lambda x: -len(x[1])):
        route = CONTEXT_ROUTES.get(ctx, DEFAULT_ROUTE)
        print(f"    {ctx}: {len(ps)} payloads → {route['url']}?{route['param']}=<payload>")

    # Group payloads by target endpoint+param for batched fuzzer calls.
    # Smart routing: full HTML payloads (starting with `<`) in "attribute" context
    # need body context instead — they're complete elements, not attribute-breakers.
    endpoint_batches = {}  # key: (url, param) -> list of payloads
    for p, ctx in sample:
        route = CONTEXT_ROUTES.get(ctx, DEFAULT_ROUTE)
        # Full HTML elements in attribute context should go to body instead
        if ctx == "attribute" and p.strip().startswith("<"):
            route = {"url": "/reflected/body", "param": "q"}
        full_url = f"{TARGET}{route['url']}"
        key = (full_url, route["param"])
        endpoint_batches.setdefault(key, []).append((p, ctx))

    print(f"\n  Routing to {len(endpoint_batches)} different endpoint+param combinations")

    results = []
    detected = 0
    executed = 0
    per_context_stats = {}

    batch_count = sum(
        (len(entries) + 4) // 5 for entries in endpoint_batches.values()
    )
    batch_idx = 0

    for (url, param), payloads in sorted(endpoint_batches.items(),
                                          key=lambda x: -len(x[1])):
        print(f"\n  → {url.split('/')[-1]}/{param}")

        for i in range(0, len(payloads), 5):
            batch = payloads[i:i+5]
            batch_idx += 1
            fuzz_payloads = [make_payload(p, param) for p, _ in batch]

            try:
                fuzz_result = api_post(FUZZER, "/fuzz", {
                    "url": url,
                    "payloads": fuzz_payloads,
                    "verify_execution": True,
                    "timeout": 60000,
                    "stored_mode": False,
                }, timeout=120)

                for r in fuzz_result.get("results", []):
                    vuln = r.get("vuln", False)
                    exec_ = r.get("executed", False)
                    refl = r.get("reflected", False)
                    if vuln:
                        detected += 1
                    if exec_:
                        executed += 1
                    results.append({
                        "payload": r.get("payload", "")[:100],
                        "vuln": vuln,
                        "executed": exec_,
                        "reflected": refl,
                        "type": r.get("type", ""),
                        "tested_on": f"{url}?{param}=<payload>",
                    })

                batch_detected = sum(
                    1 for r in fuzz_result.get("results", []) if r.get("vuln")
                )
                print(f"      Batch {batch_idx}/{batch_count}: "
                      f"{len(batch)} payloads, detected: {batch_detected}")

            except Exception as e:
                print(f"      Batch {batch_idx}/{batch_count} error: {str(e)[:80]}")

    # Build per-context breakdown from results
    for ctx in set(ctx for _, ctx in sample):
        ctx_total = sum(1 for _, c in sample if c == ctx)
        ctx_detected = 0
        ctx_executed = 0
        for p, c in sample:
            if c == ctx:
                for r in results:
                    if r["payload"][:100] == p[:100]:
                        if r["vuln"]:
                            ctx_detected += 1
                        if r["executed"]:
                            ctx_executed += 1
                        break
        per_context_stats[ctx] = {
            "total": ctx_total,
            "detected": ctx_detected,
            "executed": ctx_executed,
            "coverage_pct": round(ctx_detected / ctx_total * 100, 1) if ctx_total else 0,
        }

    coverage_pct = (detected / len(sample) * 100) if sample else 0
    execution_pct = (executed / len(sample) * 100) if sample else 0

    port_data = {
        "total_portswigger_payloads": total,
        "sample_tested": PORT_SAMPLE_SIZE,
        "detected": detected,
        "browser_executed": executed,
        "coverage_pct": round(coverage_pct, 1),
        "execution_pct": round(execution_pct, 1),
        "context_breakdown": per_context_stats,
        "routing_table": {
            ctx: f"{TARGET}{route['url']}?{route['param']}=<payload>"
            for ctx, route in CONTEXT_ROUTES.items()
        },
        "details": results,
    }

    PORT_RESULTS_FILE.write_text(json.dumps(port_data, indent=2, default=str))

    print(f"\n  Context breakdown:")
    for ctx, cd in sorted(per_context_stats.items(), key=lambda x: -x[1]["total"]):
        route = CONTEXT_ROUTES.get(ctx, DEFAULT_ROUTE)
        print(f"    {ctx:25s} {cd['total']:3d} payloads → {cd['detected']:2d} detected ({cd['coverage_pct']:.0f}%)")
    print(f"\n  PortSwigger Coverage: {detected}/{PORT_SAMPLE_SIZE} ({coverage_pct:.1f}%)")
    print(f"  Browser-Confirmed: {executed}/{PORT_SAMPLE_SIZE} ({execution_pct:.1f}%)")
    print(f"  Results saved: {PORT_RESULTS_FILE}")

    return port_data


# ── Evaluation Runner ───────────────────────────────────────────

def run_eval(endpoints):
    results = {}
    timestamp = datetime.utcnow().isoformat()

    print("=" * 70)
    print(f"  RED SENTINEL COMPREHENSIVE EVALUATION")
    print(f"  Target: {TARGET} (legacy: {TARGET_LEGACY})")
    print(f"  Endpoints: {len(endpoints)}")
    print(f"  Timestamp: {timestamp}")
    print("=" * 70)

    total_payloads = sum(len(ep.payloads) for ep in endpoints)
    print(f"\n  Total payloads: {total_payloads}")
    print()

    for idx, ep in enumerate(endpoints, 1):
        if not ep.payloads:
            print(f"  [{idx}/{len(endpoints)}] {ep.name} (SKIP — no payloads)")
            continue

        print(f"\n  [{idx}/{len(endpoints)}] {ep.name} ({ep.category})")
        print(f"      URL: {ep.url}")
        print(f"      Payloads: {len(ep.payloads)}")

        try:
            start = time.time()
            fuzz_result = api_post(FUZZER, "/fuzz", ep.to_fuzz_request(), timeout=120)
            elapsed = time.time() - start

            results_list = fuzz_result.get("results", [])
            vuln_count = sum(1 for r in results_list if r.get("vuln"))
            executed_count = sum(1 for r in results_list if r.get("executed"))
            reflected_count = sum(1 for r in results_list if r.get("reflected"))

            print(f"      Time: {elapsed:.2f}s")
            print(f"      Results: {len(results_list)} | Reflected: {reflected_count} | "
                  f"Executed: {executed_count} | Vulns: {vuln_count}")

            vulns = []
            for vr in results_list:
                if vr.get("vuln"):
                    ev = vr.get("evidence", {})
                    vulns.append({
                        "payload": vr.get("payload", "")[:120],
                        "param": vr.get("target_param", ""),
                        "type": vr.get("type", ""),
                        "position": ev.get("reflection_position", ""),
                        "executed": vr.get("executed", False),
                        "exact": ev.get("exact_match", False),
                    })

            results[ep.name] = {
                "category": ep.category,
                "url": ep.url,
                "expected": ep.expected,
                "time": round(elapsed, 2),
                "total_results": len(results_list),
                "reflected": reflected_count,
                "executed": executed_count,
                "vulns": vuln_count,
                "vuln_details": vulns,
                "error": None,
            }

        except Exception as e:
            elapsed = time.time() - start if 'start' in locals() else 0
            print(f"      Error after {elapsed:.2f}s: {str(e)[:100]}")
            results[ep.name] = {
                "category": ep.category,
                "url": ep.url,
                "expected": ep.expected,
                "time": round(elapsed, 2),
                "total_results": 0,
                "reflected": 0,
                "executed": 0,
                "vulns": 0,
                "vuln_details": [],
                "error": str(e),
            }

    return {
        "timestamp": timestamp,
        "target": TARGET,
        "target_legacy": TARGET_LEGACY,
        "endpoints": results,
        "summary": compile_summary(results),
    }


def compile_summary(results):
    """Compile aggregate metrics."""
    categories = {}
    for name, r in results.items():
        cat = r.get("category", "Other")
        if cat not in categories:
            categories[cat] = {"endpoints": 0, "vulns": 0, "executed": 0,
                               "reflected": 0, "errors": 0}
        categories[cat]["endpoints"] += 1
        categories[cat]["vulns"] += r.get("vulns", 0)
        categories[cat]["executed"] += r.get("executed", 0)
        categories[cat]["reflected"] += r.get("reflected", 0)
        if r.get("error"):
            categories[cat]["errors"] += 1

    tp = sum(1 for r in results.values()
             if r.get("expected") == "Vuln" and r.get("vulns", 0) > 0)
    fn = sum(1 for r in results.values()
             if r.get("expected") == "Vuln" and r.get("vulns", 0) == 0)
    tn = sum(1 for r in results.values()
             if r.get("expected") == "Safe" and r.get("vulns", 0) == 0)
    fp = sum(1 for r in results.values()
             if r.get("expected") == "Safe" and r.get("vulns", 0) > 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "categories": categories,
        "tp": tp, "fn": fn, "tn": tn, "fp": fp,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "total_endpoints": len(results),
        "total_vulns": sum(r.get("vulns", 0) for r in results.values()),
        "total_executed": sum(r.get("executed", 0) for r in results.values()),
        "total_reflected": sum(r.get("reflected", 0) for r in results.values()),
        "endpoints_with_errors": sum(1 for r in results.values() if r.get("error")),
    }


# ── Report Generators ──────────────────────────────────────────

def generate_markdown(data, port_data=None):
    """Generate Markdown evaluation report."""
    s = data["summary"]
    lines = []
    lines.append("# Red Sentinel Evaluation Report\n")
    lines.append(f"**Date:** {data['timestamp'][:10]}")
    lines.append(f"**Target:** {data['target']} (legacy: {data['target_legacy']})")
    lines.append(f"**Endpoints Tested:** {s['total_endpoints']}")
    lines.append(f"**Total Payloads Executed:** {s['total_executed']}")
    lines.append(f"**Total Vulnerabilities Found:** {s['total_vulns']}")
    lines.append("")

    # ── 1. Executive Summary ──
    lines.append("## 1. Executive Summary\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Precision | {s['precision']:.3f} |")
    lines.append(f"| Recall | {s['recall']:.3f} |")
    lines.append(f"| F1-Score | {s['f1']:.3f} |")
    lines.append(f"| True Positives | {s['tp']} |")
    lines.append(f"| False Negatives | {s['fn']} |")
    lines.append(f"| True Negatives | {s['tn']} |")
    lines.append(f"| False Positives | {s['fp']} |")
    if port_data:
        lines.append(f"| PortSwigger Coverage | {port_data['coverage_pct']}% |")
    lines.append("")

    # ── 2. Category Breakdown ──
    lines.append("## 2. Category Breakdown\n")
    lines.append("| Category | Endpoints | Vulns Found | Executed (Browser) | Reflected | Errors |")
    lines.append("|----------|-----------|-------------|--------------------|-----------|--------|")
    for cat, stats in sorted(s["categories"].items()):
        lines.append(f"| {cat} | {stats['endpoints']} | {stats['vulns']} | "
                      f"{stats['executed']} | {stats['reflected']} | {stats['errors']} |")
    lines.append("")

    # ── 3. Per-Endpoint Results ──
    lines.append("## 3. Per-Endpoint Results\n")
    lines.append("| Endpoint | Category | Expected | Vulns | Executed | Reflected | Time (s) |")
    lines.append("|----------|----------|----------|-------|----------|-----------|----------|")
    for name, r in sorted(data["endpoints"].items()):
        exp = r.get("expected", "Vuln")
        if r.get("error"):
            status = "⚠️"
        elif r.get("vulns", 0) > 0 or exp == "Safe":
            status = "✅"
        else:
            status = "❌"
        error_mark = " ⚠️" if r.get("error") else ""
        lines.append(f"| {name}{error_mark} | {r['category']} | {exp} | "
                      f"{r['vulns']} {status} | {r['executed']} | {r['reflected']} | {r['time']} |")
    lines.append("")

    # ── 4. Vulnerability Details ──
    lines.append("## 4. Vulnerability Details\n")
    for name, r in sorted(data["endpoints"].items()):
        vulns = r.get("vuln_details", [])
        if vulns:
            lines.append(f"### {name}\n")
            lines.append("| Payload | Param | Type | Position | Executed | Exact Match |")
            lines.append("|---------|-------|------|----------|----------|-------------|")
            for v in vulns:
                lines.append(f"| `{v['payload'][:60]}` | {v['param']} | {v['type']} | "
                              f"{v['position']} | {v['executed']} | {v['exact']} |")
            lines.append("")

    # ── 5. PortSwigger Coverage (if available) ──
    if port_data:
        lines.append("## 5. PortSwigger Payload Coverage (Multi-Context Routing)\n")
        lines.append(f"**Tested against:** {len(port_data.get('context_breakdown', {}))} different endpoint contexts")
        lines.append(f"**Total PortSwigger payloads in dataset:** {port_data['total_portswigger_payloads']}")
        lines.append(f"**Endpoints used:**")
        for ctx, route_str in sorted(port_data.get('routing_table', {}).items()):
            lines.append(f"  - `{ctx}` → `{route_str}`")
        lines.append("")
        lines.append(f"**Sample tested:** {port_data['sample_tested']}")
        lines.append(f"**Detected:** {port_data['detected']} ({port_data['coverage_pct']}%)")
        lines.append(f"**Browser-executed:** {port_data['browser_executed']} ({port_data['execution_pct']}%)")
        lines.append("")

        lines.append("### 5.1 Per-Context Coverage\n")
        lines.append("| Context | Tested | Detected | Coverage % |")
        lines.append("|---------|--------|----------|------------|")
        for ctx, cd in sorted(port_data.get("context_breakdown", {}).items(),
                              key=lambda x: -x[1]["total"]):
            lines.append(f"| {ctx} | {cd['total']} | {cd['detected']} | {cd['coverage_pct']}% |")
        lines.append("")

        lines.append("### 5.2 Payload Detail\n")
        lines.append("| Payload | Tested On | Reflected | Executed | Vuln | Type |")
        lines.append("|---------|-----------|-----------|----------|------|------|")
        for d in port_data.get("details", []):
            tested = d.get('tested_on', '').split('?')[-1] if 'tested_on' in d else ''
            lines.append(f"| `{d['payload'][:40]}` | `{tested}` | {d['reflected']} | {d['executed']} | "
                          f"{d['vuln']} | {d.get('type', '')} |")
        lines.append("")

    # ── 6. False Negatives Analysis ──
    fns = [(name, r) for name, r in sorted(data["endpoints"].items())
           if r.get("expected") == "Vuln" and r.get("vulns", 0) == 0 and not r.get("error")]
    if fns:
        lines.append("## 6. False Negatives Analysis\n")
        lines.append("| Endpoint | Category | URL | Note |")
        lines.append("|----------|----------|-----|------|")
        for name, r in fns:
            lines.append(f"| {name} | {r['category']} | `{r['url']}` | No vulns detected |")
        lines.append("")

    lines.append("---\n")
    lines.append(f"*Report generated: {data['timestamp']}*")
    lines.append(f"*Full results: `{RESULTS_FILE}`*")
    if port_data:
        lines.append(f"*PortSwigger coverage: `{PORT_RESULTS_FILE}`*")

    return "\n".join(lines)


def generate_html(data, port_data=None):
    """Generate standalone HTML benchmarking report."""
    s = data["summary"]

    style = """
    <style>
        :root {
            --bg-0: #0a0a0f;
            --bg-1: #12121a;
            --bg-2: #1a1a2e;
            --bg-3: #252540;
            --border: #2a2a45;
            --text-primary: #e8e8f0;
            --text-secondary: #a0a0b8;
            --text-muted: #6b6b80;
            --accent: #00d4ff;
            --accent2: #8b5cf6;
            --green: #34d399;
            --red: #ef4444;
            --yellow: #f59e0b;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-0);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { font-size: 2.2rem; font-weight: 700; margin-bottom: 0.5rem;
             background: linear-gradient(135deg, var(--accent), var(--accent2));
             -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        h2 { font-size: 1.4rem; font-weight: 600; margin: 2rem 0 1rem;
             color: var(--accent); border-bottom: 1px solid var(--border);
             padding-bottom: 0.5rem; }
        h3 { font-size: 1.1rem; font-weight: 600; margin: 1.5rem 0 0.75rem;
             color: var(--text-primary); }
        .meta { color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 1.5rem; }
        .meta span { display: inline-block; margin-right: 1.5rem; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                         gap: 1rem; margin: 1.5rem 0; }
        .card { background: var(--bg-2); border: 1px solid var(--border);
                border-radius: 12px; padding: 1.2rem; text-align: center;
                transition: transform 0.2s, box-shadow 0.2s; }
        .card:hover { transform: translateY(-2px); box-shadow: 0 4px 20px rgba(0,212,255,0.1); }
        .card .value { font-size: 2rem; font-weight: 700; }
        .card .label { font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem; }
        .card.perfect { border-color: var(--green); }
        .card.perfect .value { color: var(--green); }
        .card.good .value { color: var(--accent); }
        .card.warn .value { color: var(--yellow); }
        .card.bad .value { color: var(--red); }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0;
                background: var(--bg-1); border-radius: 8px; overflow: hidden; }
        th { background: var(--bg-3); color: var(--text-secondary); font-weight: 600;
             font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;
             padding: 0.75rem 1rem; text-align: left; }
        td { padding: 0.65rem 1rem; border-top: 1px solid var(--border);
             font-size: 0.9rem; }
        tr:hover td { background: rgba(0,212,255,0.03); }
        code { font-family: 'JetBrains Mono', 'Fira Code', monospace;
               font-size: 0.85em; background: var(--bg-3); padding: 0.15em 0.4em;
               border-radius: 4px; }
        .status-pass { color: var(--green); }
        .status-fail { color: var(--red); }
        .status-warn { color: var(--yellow); }
        .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
                 font-size: 0.75rem; font-weight: 600; }
        .badge-vuln { background: rgba(239,68,68,0.15); color: var(--red); }
        .badge-safe { background: rgba(52,211,153,0.15); color: var(--green); }
        .badge-info { background: rgba(0,212,255,0.15); color: var(--accent); }
        .badge-warn { background: rgba(245,158,11,0.15); color: var(--yellow); }
        .footer { margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border);
                  color: var(--text-muted); font-size: 0.85rem; }
        .chart-bar { display: flex; align-items: center; gap: 0.5rem; margin: 0.25rem 0; }
        .chart-bar .bar { height: 20px; border-radius: 4px;
                          background: linear-gradient(90deg, var(--accent), var(--accent2));
                          transition: width 0.5s ease; }
        .chart-bar .bar-label { font-size: 0.85rem; color: var(--text-secondary); min-width: 100px; }
        .vuln-detail { background: var(--bg-2); border: 1px solid var(--border);
                       border-radius: 8px; padding: 0.75rem; margin: 0.5rem 0; }
        .vuln-detail pre { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
                          color: var(--text-secondary); overflow-x: auto;
                          white-space: pre-wrap; word-break: break-word; }
    </style>
    """

    p_class = "perfect" if s["precision"] == 1.0 else ("good" if s["precision"] >= 0.8 else ("warn" if s["precision"] >= 0.5 else "bad"))
    r_class = "perfect" if s["recall"] == 1.0 else ("good" if s["recall"] >= 0.8 else ("warn" if s["recall"] >= 0.5 else "bad"))
    f1_class = "perfect" if s["f1"] == 1.0 else ("good" if s["f1"] >= 0.8 else ("warn" if s["f1"] >= 0.5 else "bad"))
    fp_class = "perfect" if s["fp"] == 0 else ("good" if s["fp"] <= 1 else ("warn" if s["fp"] <= 5 else "bad"))
    fn_class = "perfect" if s["fn"] == 0 else ("good" if s["fn"] <= 1 else ("warn" if s["fn"] <= 5 else "bad"))

    cat_rows = ""
    for cat, stats in sorted(s["categories"].items()):
        cat_rows += f"<tr><td>{cat}</td><td>{stats['endpoints']}</td><td>{stats['vulns']}</td><td>{stats['executed']}</td><td>{stats['reflected']}</td><td>{'⚠️' if stats['errors'] > 0 else '✅'}</td></tr>\n"

    ep_rows = ""
    for name, r in sorted(data["endpoints"].items()):
        exp = r.get("expected", "Vuln")
        v = r.get("vulns", 0)
        if r.get("error"):
            status = "<span class='status-warn'>⚠️</span>"
            badge = "<span class='badge badge-warn'>ERROR</span>"
        elif v > 0:
            status = "<span class='status-pass'>✅</span>"
            badge = "<span class='badge badge-vuln'>VULN</span>"
        elif exp == "Safe":
            status = "<span class='status-pass'>✅</span>"
            badge = "<span class='badge badge-safe'>SAFE</span>"
        else:
            status = "<span class='status-fail'>❌</span>"
            badge = "<span class='badge badge-warn'>MISSED</span>"
        error_icon = " ⚠️" if r.get("error") else ""
        ep_rows += f"<tr><td>{name}{error_icon}</td><td>{r['category']}</td><td>{exp}</td><td>{badge}</td><td>{v}</td><td>{r['executed']}</td><td>{r['reflected']}</td><td>{r['time']}s</td></tr>\n"

    vuln_sections = ""
    for name, r in sorted(data["endpoints"].items()):
        vulns = r.get("vuln_details", [])
        if vulns:
            vuln_sections += f"<h3>{name}</h3>\n"
            vuln_sections += '<div class="vuln-detail">\n'
            for v in vulns:
                vuln_sections += f'<pre><span class="badge badge-info">{v["type"]}</span> '
                vuln_sections += f'param=<strong>{v["param"]}</strong> '
                vuln_sections += f'pos=<strong>{v["position"]}</strong> '
                vuln_sections += f'exec={v["executed"]} '
                vuln_sections += f'exact={v["exact"]}</pre>\n'
                vuln_sections += f'<pre>  Payload: {v["payload"][:80]}</pre>\n'
            vuln_sections += '</div>\n'

    # Bar charts
    max_vulns = max((stats["vulns"] for stats in s["categories"].values()), default=1)
    chart_bars = ""
    for cat, stats in sorted(s["categories"].items()):
        pct = (stats["vulns"] / max_vulns * 100) if max_vulns > 0 else 0
        chart_bars += f'<div class="chart-bar"><span class="bar-label">{cat}</span>'
        chart_bars += f'<div class="bar" style="width:{pct:.0f}%"></div>'
        chart_bars += f'<span style="font-size:0.85rem">{stats["vulns"]}</span></div>\n'

    # PortSwigger section
    port_html = ""
    if port_data:
        port_html += '<h2>🧪 PortSwigger Payload Coverage</h2>\n'
        port_html += f'<p>Tested <strong>{port_data["sample_tested"]}</strong> PortSwigger payloads against <code>{TARGET}/reflected/body</code></p>\n'
        port_html += '<div style="display:flex;gap:1rem;margin:1rem 0">\n'
        cov_class = "perfect" if port_data["coverage_pct"] >= 90 else ("good" if port_data["coverage_pct"] >= 70 else "warn")
        exec_class = "perfect" if port_data["execution_pct"] >= 70 else ("good" if port_data["execution_pct"] >= 50 else "warn")
        port_html += f'<div class="card {cov_class}" style="flex:1"><div class="value">{port_data["coverage_pct"]}%</div><div class="label">Detection Rate</div></div>\n'
        port_html += f'<div class="card {exec_class}" style="flex:1"><div class="value">{port_data["execution_pct"]}%</div><div class="label">Browser-Confirmed</div></div>\n'
        port_html += '</div>\n'

        if port_data.get("context_breakdown"):
            port_html += '<h3>Per-Context Breakdown</h3>\n<table>\n<tr><th>Context</th><th>Tested</th><th>Detected</th><th>Coverage</th></tr>\n'
            for ctx, cd in sorted(port_data["context_breakdown"].items(), key=lambda x: -x[1]["total"]):
                port_html += f'<tr><td>{ctx}</td><td>{cd["total"]}</td><td>{cd["detected"]}</td><td>{cd["coverage_pct"]}%</td></tr>\n'
            port_html += '</table>\n'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Red Sentinel Benchmark Report</title>
{style}
</head>
<body>
<div class="container">

<h1>🔴 Red Sentinel Benchmark Report</h1>
<div class="meta">
    <span>📅 {data['timestamp'][:10]}</span>
    <span>🎯 Target: <code>{data['target']}</code></span>
    <span>📋 Endpoints: <strong>{s['total_endpoints']}</strong></span>
    <span>⚡ Vulns Found: <strong>{s['total_vulns']}</strong></span>
    <span>🖥️ Browser-Confirmed: <strong>{s['total_executed']}</strong></span>
</div>

<h2>📊 Executive Summary</h2>
<div class="summary-cards">
    <div class="card {p_class}">
        <div class="value">{s['precision']:.3f}</div>
        <div class="label">Precision</div>
    </div>
    <div class="card {r_class}">
        <div class="value">{s['recall']:.3f}</div>
        <div class="label">Recall</div>
    </div>
    <div class="card {f1_class}">
        <div class="value">{s['f1']:.3f}</div>
        <div class="label">F1-Score</div>
    </div>
    <div class="card">
        <div class="value">{s['tp']}</div>
        <div class="label">True Positives</div>
    </div>
    <div class="card {fn_class}">
        <div class="value">{s['fn']}</div>
        <div class="label">False Negatives</div>
    </div>
    <div class="card">
        <div class="value">{s['tn']}</div>
        <div class="label">True Negatives</div>
    </div>
    <div class="card {fp_class}">
        <div class="value">{s['fp']}</div>
        <div class="label">False Positives</div>
    </div>
</div>

{port_html}

<h2>📈 Vulnerability Distribution by Category</h2>
{chart_bars}

<h2>📋 Category Breakdown</h2>
<table>
<tr><th>Category</th><th>Endpoints</th><th>Vulns</th><th>Executed</th><th>Reflected</th><th>Status</th></tr>
{cat_rows}
</table>

<h2>🔍 Per-Endpoint Results</h2>
<table>
<tr><th>Endpoint</th><th>Category</th><th>Expected</th><th>Result</th><th>Vulns</th><th>Executed</th><th>Reflected</th><th>Time</th></tr>
{ep_rows}
</table>

<h2>🔬 Vulnerability Details</h2>
{vuln_sections}

<div class="footer">
    <p>Report generated: {data['timestamp']}</p>
    <p>Full results JSON: <code>{RESULTS_FILE}</code></p>
    <p>PortSwigger coverage: <code>{PORT_RESULTS_FILE}</code></p>
    <p>Red Sentinel — AI-powered XSS detection engine</p>
</div>

</div>
</body>
</html>
"""


# ── Main ────────────────────────────────────────────────────────

def main():
    OUTPUTS.mkdir(parents=True, exist_ok=True)

    # Phase 1: PortSwigger coverage analysis
    print("PHASE 1: PortSwigger Payload Coverage Analysis\n")
    port_data = run_portswigger_coverage()

    # Phase 2: Comprehensive endpoint evaluation
    print(f"\n{'='*70}")
    print("PHASE 2: Endpoint Evaluation")
    print(f"{'='*70}\n")

    endpoints = build_endpoints()
    print(f"Building endpoint definitions: {len(endpoints)} endpoints\n")

    data = run_eval(endpoints)
    s = data["summary"]

    # Save raw results
    data["portswigger"] = port_data
    RESULTS_FILE.write_text(json.dumps(data, indent=2, default=str))

    # Print summary
    print("\n" + "=" * 70)
    print("  RESULTS SUMMARY")
    print("=" * 70)
    print(f"  Endpoints: {s['total_endpoints']}")
    print(f"  Vulnerabilities: {s['total_vulns']} (browser-confirmed: {s['total_executed']})")
    print(f"  TP={s['tp']}, FN={s['fn']}, TN={s['tn']}, FP={s['fp']}")
    print(f"  Precision: {s['precision']:.3f}")
    print(f"  Recall:    {s['recall']:.3f}")
    print(f"  F1-score:  {s['f1']:.3f}")
    if port_data:
        print(f"  PortSwigger Coverage: {port_data['coverage_pct']}%")
    print(f"  Endpoints with errors: {s['endpoints_with_errors']}")

    # Generate reports
    md = generate_markdown(data, port_data)
    REPORT_MD.write_text(md)
    print(f"\n✅ Markdown report: {REPORT_MD}")

    html = generate_html(data, port_data)
    REPORT_HTML.write_text(html)
    print(f"✅ HTML report: {REPORT_HTML}")

    # Also save the PortSwigger results
    results_summary = {
        "endpoints_tested": s["total_endpoints"],
        "vulns_found": s["total_vulns"],
        "browser_confirmed": s["total_executed"],
        "precision": s["precision"],
        "recall": s["recall"],
        "f1": s["f1"],
        "portswigger_coverage_pct": port_data["coverage_pct"] if port_data else None,
    }
    summary_file = OUTPUTS / "rs_benchmark_summary.json"
    summary_file.write_text(json.dumps(results_summary, indent=2))
    print(f"✅ Benchmark summary: {summary_file}")
    print(f"✅ Raw results: {RESULTS_FILE}")
    print("Done.")


if __name__ == "__main__":
    main()
