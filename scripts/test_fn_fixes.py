#!/usr/bin/env python3
"""Test the two false-negative fix payloads through the fuzzer."""
import json
import urllib.request
import urllib.error

FUZZER = "http://localhost:5003"
TARGET = "http://localhost:9090"


def make_payload(p, param):
    return {"payload": p, "target_param": param, "confidence": 1.0, "technique": "original", "severity": "medium"}


def test(url, payloads, desc):
    print(f"\n=== {desc} ===")
    data = {
        "url": url,
        "payloads": payloads,
        "verify_execution": True,
        "timeout": 60000,
        "stored_mode": False,
    }
    req = urllib.request.Request(
        f"{FUZZER}/fuzz",
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = urllib.request.urlopen(req, timeout=60)
        results = json.loads(resp.read().decode())
        for r in results.get("results", []):
            p = r.get("payload", "")[:60]
            v = r.get("vuln", False)
            e = r.get("executed", False)
            refl = r.get("reflected", False)
            tp = r.get("type", "?")
            print(f"  {'✅' if v else '❌'} vuln={v} exec={e} refl={refl} type={tp} | {p}")
        vuln_count = sum(1 for r in results.get("results", []) if r.get("vuln"))
        print(f"  -> {vuln_count}/{len(payloads)} vulns detected")
    except Exception as ex:
        print(f"  Error: {ex}")


# ── Test 1: WAF-sim ──
# Blocklist: alert, prompt, confirm, eval, onerror, onload
# Split alert via string concatenation: 'ale' + 'rt(1)' -> alert(1)
test(
    f"{TARGET}/bypass/waf-sim",
    [
        make_payload('<input autofocus onfocus="setTimeout(\'ale\'+\'rt(1)\')">', "q"),
        make_payload('<input autofocus onfocus="setTimeout(\'con\'+\'firm(1)\')">', "q"),
    ],
    "bypass-waf-sim (split alert/confirm)",
)

# ── Test 2: Comment strip (no comment wrapper) ──
# The filter strips <!--...-->, so wrapping in comments means the response
# has the unwrapped version -> the fuzzer's reflection check fails because
# the SENT payload doesn't match the RESPONSE payload.
# Fix: send the payload WITHOUT the comment wrapper.
test(
    f"{TARGET}/bypass/comment",
    [
        make_payload('<img src=x onerror=alert(1)>', "q"),
        make_payload('<svg onload=alert(1)>', "q"),
    ],
    "bypass-comment (no comment wrapper)",

)

print("\nDone.")
