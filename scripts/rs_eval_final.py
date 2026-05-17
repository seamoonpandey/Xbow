#!/usr/bin/env python3
"""Run Red Sentinel fuzzer pipeline with verify_execution=True on all 4 test cases."""

import json
import urllib.request
import urllib.error
import time

CONTEXT = "http://localhost:5001"
PAYLOAD = "http://localhost:5002"
FUZZER = "http://localhost:5003"


def api_post(base, endpoint, data, timeout=60):
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
        print(f"  HTTP {e.code}: {body[:300]}")
        raise
    except Exception as e:
        print(f"  Error: {e}")
        raise


def make_payload(payload_str, param):
    """Create a FuzzPayload dict for the given param."""
    return {"payload": payload_str, "target_param": param, "confidence": 1.0, "technique": "original", "severity": "medium"}


# Test case definitions with correct target params per case
test_cases = [
    {
        "name": "T1",
        "url": "http://localhost:8081/t1",
        "params": ["q"],
        "method": "GET",
        "expected": "Vuln",
        "payloads": [
            make_payload('<script>alert(1)</script>', "q"),
            make_payload('<img src=x onerror=alert(1)>', "q"),
            make_payload('" onfocus=alert(1) autofocus="', "q"),
            make_payload("<script>alert(String.fromCharCode(88,83,83))</script>", "q"),
            make_payload('<svg onload=alert(1)>', "q"),
            make_payload('<body onload=alert(1)>', "q"),
            make_payload('javascript:alert(1)', "q"),
            make_payload('"><script>alert(1)</script>', "q"),
            make_payload("'><script>alert(1)</script>", "q"),
            make_payload('</script><script>alert(1)</script>', "q"),
            make_payload('<script>prompt(1)</script>', "q"),
            make_payload('<script>confirm(1)</script>', "q"),
        ],
    },
    {
        "name": "T2",
        "url": "http://localhost:8081/t2",
        "params": ["q"],
        "method": "GET",
        "expected": "Safe",
        "payloads": [
            make_payload('<script>alert(1)</script>', "q"),
            make_payload('<img src=x onerror=alert(1)>', "q"),
            make_payload('" onfocus=alert(1) autofocus="', "q"),
            make_payload("<script>alert(String.fromCharCode(88,83,83))</script>", "q"),
            make_payload('<svg onload=alert(1)>', "q"),
            make_payload('<body onload=alert(1)>', "q"),
            make_payload('javascript:alert(1)', "q"),
            make_payload('"><script>alert(1)</script>', "q"),
            make_payload("'><script>alert(1)</script>", "q"),
            make_payload('</script><script>alert(1)</script>', "q"),
            make_payload('<script>prompt(1)</script>', "q"),
            make_payload('<script>confirm(1)</script>', "q"),
        ],
    },
    {
        "name": "T3",
        "url": "http://localhost:8081/t3",
        "params": ["name"],
        "method": "GET",
        "expected": "Vuln",
        "payloads": [
            make_payload('<script>alert(1)</script>', "name"),
            make_payload('<img src=x onerror=alert(1)>', "name"),
            make_payload('" onfocus=alert(1) autofocus="', "name"),
            make_payload("<script>alert(String.fromCharCode(88,83,83))</script>", "name"),
            make_payload('<svg onload=alert(1)>', "name"),
            make_payload('<body onload=alert(1)>', "name"),
            make_payload('javascript:alert(1)', "name"),
            make_payload('"><script>alert(1)</script>', "name"),
            make_payload("'><script>alert(1)</script>", "name"),
            make_payload('</script><script>alert(1)</script>', "name"),
            make_payload('<script>prompt(1)</script>', "name"),
            make_payload('<script>confirm(1)</script>', "name"),
        ],
    },
    {
        "name": "T4",
        "url": "http://localhost:8081/t4",
        "params": ["txtName", "mtxMessage"],
        "method": "POST",
        "expected": "Vuln",
        "stored_mode": True,
        "display_url": "http://localhost:8081/t4",
        "payloads": [
            make_payload('<script>alert(1)</script>', "mtxMessage"),
            make_payload('<img src=x onerror=alert(1)>', "mtxMessage"),
            make_payload('" onfocus=alert(1) autofocus="', "txtName"),
            make_payload("<script>alert(String.fromCharCode(88,83,83))</script>", "mtxMessage"),
            make_payload('<svg onload=alert(1)>', "mtxMessage"),
            make_payload('<body onload=alert(1)>', "mtxMessage"),
            make_payload('javascript:alert(1)', "txtName"),
            make_payload('"><script>alert(1)</script>', "mtxMessage"),
            make_payload("'><script>alert(1)</script>", "mtxMessage"),
            make_payload('</script><script>alert(1)</script>', "mtxMessage"),
            make_payload('<script>prompt(1)</script>', "txtName"),
            make_payload('<script>confirm(1)</script>', "mtxMessage"),
        ],
    },
]

results = {}

print("=" * 70)
print("  RED SENTINEL EVALUATION - verify_execution=True")
print("  Testing decoded-only reflection FP fix for T2 (safe page)")
print("=" * 70)

for tc in test_cases:
    name = tc["name"]
    print(f"\n{'='*60}")
    print(f"  {name}: {tc['url']}  (expected: {tc['expected']})")
    print(f"{'='*60}")

    # Step 1: Context analysis
    print(f"\n[Step 1] Context analysis...")
    try:
        ctx_result = api_post(CONTEXT, "/analyze", {
            "url": tc["url"],
            "params": tc["params"],
            "waf": "none",
        })
        print(f"  Context: {json.dumps(ctx_result)[:400]}")
    except Exception as e:
        print(f"  Context analysis failed: {e}")

    # Step 2: Run fuzzer
    tc_payloads = tc["payloads"]
    print(f"\n[Step 2] Fuzzing with {len(tc_payloads)} payloads (verify_execution=True)...")

    if tc.get("stored_mode"):
        form_fields = {p: ("Alice" if p == "txtName" else "HelloWorld") for p in tc["params"]}
        fuzz_request = {
            "url": tc["url"],
            "payloads": tc_payloads,
            "verify_execution": True,
            "timeout": 30000,
            "stored_mode": True,
            "display_url": tc["display_url"],
            "form_fields": form_fields,
        }
    else:
        fuzz_request = {
            "url": tc["url"],
            "payloads": tc_payloads,
            "verify_execution": True,
            "timeout": 30000,
            "stored_mode": False,
        }

    start = time.time()
    try:
        fuzz_result = api_post(FUZZER, "/fuzz", fuzz_request, timeout=120)
        elapsed = time.time() - start

        results_list = fuzz_result.get("results", [])
        vuln_count = sum(1 for r in results_list if r.get("vuln"))
        executed_count = sum(1 for r in results_list if r.get("executed"))
        reflected_count = sum(1 for r in results_list if r.get("reflected"))

        print(f"  Time: {elapsed:.2f}s")
        print(f"  Total results: {len(results_list)}")
        print(f"  Reflected: {reflected_count}")
        print(f"  Executed (Playwright): {executed_count}")
        print(f"  Flagged vuln: {vuln_count}")

        vuln_results = [r for r in results_list if r.get("vuln")]
        if vuln_results:
            print(f"\n  Vulnerability Details:")
            for vr in vuln_results:
                ev = vr.get("evidence", {})
                print(f"    - {vr.get('type','?')} | param={vr.get('target_param','?')} "
                      f"| pos={ev.get('reflection_position','?')} "
                      f"| executed={vr.get('executed')} | exact={ev.get('exact_match','?')}")
                print(f"      payload: {vr.get('payload','?')[:80]}")

        results[name] = {
            "results": results_list,
            "time": elapsed,
            "vulns": vuln_count,
            "executed": executed_count,
            "reflected": reflected_count,
        }

    except Exception as e:
        elapsed = time.time() - start
        print(f"  Error after {elapsed:.2f}s: {e}")
        results[name] = {"error": str(e), "time": elapsed}

# Compile results
print("\n" + "=" * 70)
print("  RESULTS SUMMARY (verify_execution=True)")
print("=" * 70)
print(f"\n{'Test':5} | {'Vulns':6} | {'Executed':8} | {'Reflectd':10} | {'Time':6} | {'Expected':12}")
print("-" * 55)

for tc in test_cases:
    name = tc["name"]
    r = results.get(name, {})
    if "error" in r:
        print(f"{name:5} | ERROR: {str(r['error'])[:45]}")
    else:
        print(f"{name:5} | {r.get('vulns',0):6} | {r.get('executed',0):8} | "
              f"{r.get('reflected',0):10} | {r.get('time',0):5.2f}s | {tc['expected']:12}")

# Calculate metrics
expected_vuln = [tc["name"] for tc in test_cases if tc["expected"] == "Vuln"]
expected_safe = [tc["name"] for tc in test_cases if tc["expected"] == "Safe"]

tp = sum(1 for n in expected_vuln if results.get(n, {}).get("vulns", 0) > 0)
fn = sum(1 for n in expected_vuln if results.get(n, {}).get("vulns", 0) == 0)
tn = sum(1 for n in expected_safe if results.get(n, {}).get("vulns", 0) == 0)
fp = sum(1 for n in expected_safe if results.get(n, {}).get("vulns", 0) > 0)

precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

print(f"\n{'='*70}")
print("  METRICS")
print(f"{'='*70}")
print(f"  TP={tp}, FN={fn}, TN={tn}, FP={fp}")
print(f"  Precision: {precision:.3f}")
print(f"  Recall:    {recall:.3f}")
print(f"  F1-score:  {f1:.3f}")

# Save results
output = {
    "test_cases": [
        {
            "name": tc["name"],
            "expected": tc["expected"],
            "results": results.get(tc["name"], {}),
        }
        for tc in test_cases
    ],
    "summary": {
        "tp": tp,
        "fn": fn,
        "tn": tn,
        "fp": fp,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    },
    "timestamp": time.time(),
}

with open("/home/moon/Projects/xbow/outputs/rs_browser_verify_results.json", "w") as f:
    json.dump(output, f, indent=2, default=str)

print(f"\nResults saved to outputs/rs_browser_verify_results.json")
print("Done.")
