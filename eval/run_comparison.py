#!/usr/bin/env python3
"""
eval/run_comparison.py — Clean, Reproducible Cross-Tool Comparison Runner

Runs Red Sentinel, XSStrike, Dalfox, and OWASP ZAP against a standard set
of endpoints with authoritative ground truth. Outputs standardized JSON
results and a clean console report with TP/FP/FN/TN metrics per tool.

Usage:
    python3 eval/run_comparison.py                          # run all endpoints
    python3 eval/run_comparison.py --limit 5                # first N endpoints
    python3 eval/run_comparison.py --skip red_sentinel      # skip a tool
    python3 eval/run_comparison.py --output my_results      # custom output path
    python3 eval/run_comparison.py --resume results.json    # re-report from saved data

Requirements:
    - Exploitable app running on http://localhost:5050
    - Red Sentinel fuzzer on http://localhost:5003
    - XSStrike, Dalfox, zap-cli installed and on PATH

Output:
    eval/comparison_results/<run_id>/
        _meta.json              — run metadata (tools, versions, timestamps)
        ground_truth.json       — frozen copy of ground truth used
        manifest.json           — frozen copy of endpoint manifest used
        per_endpoint.json       — per-endpoint per-tool detailed results
        aggregate.json          — aggregate TP/FP/FN/TN per tool
        report.txt              — human-readable console report
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


# ── ANSI escape sequence regex for stripping color codes ─────
ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*m')

ROOT = Path(__file__).resolve().parent.parent
EVAL_DIR = ROOT / "eval"
OUTPUT_DIR = EVAL_DIR / "comparison_results"

# ── Tool configuration ────────────────────────────────────────
FUZZER_URL = os.environ.get("FUZZER_URL", "http://localhost:5003")
TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:5050")

GROUND_TRUTH_PATH = EVAL_DIR / "ground_truth.json"
MANIFEST_PATH = EVAL_DIR / "manifests" / "multi-type.json"

TOOLS = ["red_sentinel", "xsstrike", "dalfox", "zap"]


# ── Data Loading ──────────────────────────────────────────────

def load_json(path):
    with open(path) as f:
        return json.load(f)


def load_ground_truth():
    """Load authoritative ground truth. Returns dict of endpoint -> expected."""
    gt = load_json(GROUND_TRUTH_PATH)
    return {name: ep["expected"] for name, ep in gt["endpoints"].items()}


def load_manifest():
    """Load endpoint manifest. Returns list of endpoint dicts."""
    return load_json(MANIFEST_PATH)


def get_tool_versions():
    """Capture versions of all tools for reproducibility tracking."""
    versions = {}
    try:
        r = subprocess.run(["python3", "--version"], capture_output=True, text=True, timeout=10)
        versions["python"] = r.stdout.strip() or r.stderr.strip()
    except Exception as e:
        versions["python"] = f"error: {e}"

    try:
        r = subprocess.run(["xsstrike", "--version"], capture_output=True, text=True, timeout=10)
        versions["xsstrike"] = (r.stdout or r.stderr).split("\n")[0].strip()
    except Exception as e:
        versions["xsstrike"] = f"error: {e}"

    try:
        r = subprocess.run(["dalfox", "version"], capture_output=True, text=True, timeout=10)
        versions["dalfox"] = (r.stdout or r.stderr).split("\n")[0].strip()
    except Exception as e:
        versions["dalfox"] = f"error: {e}"

    try:
        r = subprocess.run(["pip3", "show", "zapcli"], capture_output=True, text=True, timeout=10)
        for line in (r.stdout or "").split("\n"):
            if "Version:" in line:
                versions["zap"] = line.split("Version:")[-1].strip()
                break
    except Exception as e:
        versions["zap"] = f"error: {e}"

    return versions


# ── Tool Runners ──────────────────────────────────────────────

def make_payload(payload_str, param):
    return {
        "payload": payload_str,
        "target_param": param,
        "confidence": 1.0,
        "technique": "original",
        "severity": "medium",
    }


def run_red_sentinel(endpoint):
    """Run Red Sentinel fuzzer via its API.

    Returns dict with detected (bool), vuln_count, executed_count,
    reflected_count, details list, and raw response.
    """
    url = endpoint["url"]
    payloads = []
    for p in endpoint.get("payloads", []):
        payloads.append(make_payload(p["payload"], p["target_param"]))

    fuzz_request = {
        "url": url,
        "payloads": payloads,
        "verify_execution": True,
        "timeout": 60000,
        "stored_mode": endpoint.get("stored_mode", False),
    }

    req = urllib.request.Request(
        f"{FUZZER_URL}/fuzz",
        data=json.dumps(fuzz_request).encode(),
        headers={"Content-Type": "application/json"},
    )

    start = time.time()
    try:
        resp = urllib.request.urlopen(req, timeout=120)
        result = json.loads(resp.read().decode())
        elapsed = time.time() - start

        results_list = result.get("results", [])
        vuln_count = sum(1 for r in results_list if r.get("vuln"))
        executed_count = sum(1 for r in results_list if r.get("executed"))
        reflected_count = sum(1 for r in results_list if r.get("reflected"))

        details = []
        for vr in results_list:
            if vr.get("vuln"):
                ev = vr.get("evidence", {})
                details.append({
                    "payload": vr.get("payload", "")[:120],
                    "param": vr.get("target_param", ""),
                    "type": vr.get("type", ""),
                    "executed": vr.get("executed", False),
                    "reflected": vr.get("reflected", False),
                    "position": ev.get("reflection_position", ""),
                })

        return {
            "detected": vuln_count > 0,
            "vuln_count": vuln_count,
            "executed_count": executed_count,
            "reflected_count": reflected_count,
            "total_payloads": len(payloads),
            "total_results": len(results_list),
            "time_seconds": round(elapsed, 2),
            "details": details,
            "error": None,
        }
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        elapsed = time.time() - start
        return {"detected": False, "vuln_count": 0, "executed_count": 0,
                "reflected_count": 0, "total_payloads": len(payloads),
                "total_results": 0, "time_seconds": round(elapsed, 2),
                "details": [], "error": f"HTTP {e.code}: {body[:200]}"}
    except Exception as e:
        elapsed = time.time() - start
        return {"detected": False, "vuln_count": 0, "executed_count": 0,
                "reflected_count": 0, "total_payloads": len(payloads),
                "total_results": 0, "time_seconds": round(elapsed, 2),
                "details": [], "error": str(e)}


def run_xsstrike(endpoint):
    """Run XSStrike against a single endpoint URL.

    XSStrike outputs detection results to stdout. We parse for:
    - [+] Payload: → a payload was found (actual XSS finding)
    - [!] Reflections found → reflection detected
    - Payload count from [+] Payload: lines

    Note: uses shell=True because pyenv shims don't resolve via subprocess list args.
    """
    url = endpoint["url"]

    start = time.time()
    try:
        # Use shell=True for pyenv shim compatibility
        cmd = f"xsstrike -u {url} --timeout 30"
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=120, shell=True)
        elapsed = time.time() - start
        output = result.stdout + result.stderr

        # Strip ANSI escape sequences before parsing — XSStrike uses color codes
        clean_output = re.sub(r'\x1b\[[0-9;]*m', '', output)

        # Parse detection markers — only actual [+] Payload: lines count as findings
        payloads_found = re.findall(r'\[\+]\s*Payload:\s*(.+)', clean_output)
        reflections_found = re.findall(r'\[!]\s*Reflections?\s*found:\s*(\d+)', clean_output)
        # Use len(payloads_found) > 0 instead of broad [+] check to avoid banner FPs
        has_findings = len(payloads_found) > 0

        details = []
        for p in payloads_found[:10]:
            details.append({"payload": p.strip()[:120]})

        return {
            "detected": has_findings,
            "payloads_found": len(payloads_found),
            "reflection_count": int(reflections_found[0]) if reflections_found else 0,
            "total_output_bytes": len(output),
            "details": details,
            "time_seconds": round(elapsed, 2),
            "error": None,
            "raw_tail": output[-500:] if len(output) > 500 else output,
        }
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        return {"detected": False, "payloads_found": 0, "reflection_count": 0,
                "total_output_bytes": 0, "details": [],
                "time_seconds": round(elapsed, 2), "error": "timeout (120s)"}
    except FileNotFoundError:
        return {"detected": False, "payloads_found": 0, "reflection_count": 0,
                "total_output_bytes": 0, "details": [],
                "time_seconds": 0, "error": "xsstrike not found on PATH"}
    except Exception as e:
        elapsed = time.time() - start
        return {"detected": False, "payloads_found": 0, "reflection_count": 0,
                "total_output_bytes": 0, "details": [],
                "time_seconds": round(elapsed, 2), "error": str(e)}


def run_dalfox(endpoint):
    """Run Dalfox against a single endpoint URL.

    Dalfox reports found XSS with [POC][V] markers in stdout.
    Actual format from testing: [POC][V][GET][inHTML-URL] http://...
    If Dalfox finds nothing, it outputs a summary showing 0 issues.

    Note: uses shell=True because pyenv shims don't resolve via subprocess list args.
    """
    url = endpoint["url"]

    start = time.time()
    try:
        # Remove --silence to ensure POC markers appear in output
        cmd = f"dalfox url {url}"
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=120, shell=True)
        elapsed = time.time() - start
        # Dalfox outputs banner to stderr, POCs to stdout
        output = result.stdout + result.stderr

        # Actual format seen: [POC][V][GET][inHTML-URL] http://...
        poc_lines = re.findall(r'\[POC\]\[V\].*', output)
        # Also check for [POC][G] just in case
        poc_lines_g = re.findall(r'\[POC\]\[G\].*', output)
        all_poc = poc_lines + poc_lines_g

        vuln_lines = re.findall(r'\[V\]\[.*?\].*', output)
        has_poc = len(all_poc) > 0

        details = []
        for line in all_poc[:10]:
            details.append({"poc": line.strip()[:150]})

        return {
            "detected": has_poc,
            "poc_count": len(all_poc),
            "vuln_lines": len(vuln_lines),
            "details": details,
            "time_seconds": round(elapsed, 2),
            "error": None,
            "raw_tail": output[-500:] if len(output) > 500 else output,
        }
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        return {"detected": False, "poc_count": 0, "vuln_lines": 0,
                "details": [], "time_seconds": round(elapsed, 2),
                "error": "timeout (120s)"}
    except FileNotFoundError:
        return {"detected": False, "poc_count": 0, "vuln_lines": 0,
                "details": [], "time_seconds": 0,
                "error": "dalfox not found on PATH"}
    except Exception as e:
        elapsed = time.time() - start
        return {"detected": False, "poc_count": 0, "vuln_lines": 0,
                "details": [], "time_seconds": round(elapsed, 2),
                "error": str(e)}


def run_zap(endpoint):
    """Run OWASP ZAP via zap-cli quick-scan against a single endpoint URL.

    ZAP reports alerts as a formatted table. We parse for:
    - "Issues found: N" → total alerts count
    - Alert names and risks from the table output
    - RC=1 means alerts found, RC=0 means clean

    Note: URL is positional (no -t flag), and uses shell=True for pyenv shim.
    """
    url = endpoint["url"]

    start = time.time()
    try:
        # Correct syntax: URL is positional, no -t flag
        cmd = f"zap-cli quick-scan {url} -o PASSED,FAILED"
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=120, shell=True)
        elapsed = time.time() - start
        output = result.stdout + result.stderr

        # Parse for alert count
        issues_match = re.search(r'Issues found:\s*(\d+)', output)
        total_alerts = int(issues_match.group(1)) if issues_match else 0

        # Parse alert names and risks from the table output
        alert_names = re.findall(r'\|\s*(.+?)\s*\|\s*(High|Medium|Low|Informational)', output)
        xss_alerts_list = []
        for name, risk in alert_names:
            if any(w in name.lower() for w in ["xss", "cross", "script", "dom"]):
                xss_alerts_list.append({"alert": name.strip(), "risk": risk})

        # ZAP returns exit code 1 when alerts are found
        detected = result.returncode == 1

        # Extract unique alert type counts
        alert_type_count = {}
        for name, risk in alert_names:
            key = name.strip().lower().replace(" ", "-").replace("/", "-")[:40]
            alert_type_count[key] = alert_type_count.get(key, 0) + 1

        details = []
        for alert in xss_alerts_list[:10]:
            details.append(f"{alert['risk']}: {alert['alert']}")
        if not details:
            details_raw = [l.strip()[:150] for l in output.split("\n") if l.strip()][-5:]
            details = details_raw

        return {
            "detected": detected,
            "total_alerts": total_alerts,
            "xss_alerts": xss_alerts_list,
            "alert_type_counts": alert_type_count,
            "details": details[:15],
            "return_code": result.returncode,
            "time_seconds": round(elapsed, 2),
            "error": None,
            "raw_tail": output[-500:] if len(output) > 500 else output,
        }
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        return {"detected": False, "total_alerts": 0, "xss_alerts": [],
                "alert_type_counts": {}, "details": [],
                "return_code": None, "time_seconds": round(elapsed, 2),
                "error": "timeout (120s)"}
    except FileNotFoundError:
        return {"detected": False, "total_alerts": 0, "xss_alerts": [],
                "alert_type_counts": {}, "details": [],
                "return_code": None, "time_seconds": 0,
                "error": "zap-cli not found on PATH"}
    except Exception as e:
        elapsed = time.time() - start
        return {"detected": False, "total_alerts": 0, "xss_alerts": [],
                "alert_type_counts": {}, "details": [],
                "return_code": None, "time_seconds": round(elapsed, 2),
                "error": str(e)}


# ── Orchestrator ──────────────────────────────────────────────

TOOL_RUNNERS = {
    "red_sentinel": run_red_sentinel,
    "xsstrike": run_xsstrike,
    "dalfox": run_dalfox,
    "zap": run_zap,
}

TOOL_LABELS = {
    "red_sentinel": "Red Sentinel",
    "xsstrike": "XSStrike",
    "dalfox": "Dalfox",
    "zap": "OWASP ZAP",
}


def run_endpoint(endpoint, tools_to_run, ground_truth):
    """Run all selected tools against a single endpoint.

    Returns dict with endpoint info, ground truth, and per-tool results.
    """
    name = endpoint["name"]
    expected = ground_truth.get(name, "Unknown")

    # Build the URL with the first param for non-Red Sentinel tools
    url = endpoint["url"]
    if not url.startswith("http"):
        url = f"{TARGET_URL}{url}"

    # Store the full URL for CLI tools and the original for the fuzzer
    ep_for_cli = dict(endpoint)
    ep_for_cli["url"] = url

    tool_results = {}
    for tool_name in tools_to_run:
        runner = TOOL_RUNNERS[tool_name]
        tool_results[tool_name] = runner(ep_for_cli)

    return {
        "name": name,
        "category": endpoint.get("category", "Other"),
        "url": url,
        "params": endpoint.get("params", []),
        "expected": expected,
        "tool_results": tool_results,
    }


def compute_metrics(all_results, tools_to_run, ground_truth):
    """Compute TP/FP/FN/TN per tool against ground truth.

    "Partially" endpoints are excluded from strict metrics (they're edge cases).
    """
    # Categorize endpoints
    vuln_names = {name for name, exp in ground_truth.items() if exp == "Vuln"}
    safe_names = {name for name, exp in ground_truth.items() if exp == "Safe"}

    metrics = {}
    for tool in tools_to_run:
        tp = fn = fp = tn = 0
        partial_tp = partial_fp = 0

        for ep_result in all_results:
            name = ep_result["name"]
            expected = ep_result["expected"]
            detected = ep_result["tool_results"].get(tool, {}).get("detected", False)

            if expected == "Vuln":
                if detected:
                    tp += 1
                else:
                    fn += 1
            elif expected == "Safe":
                if detected:
                    fp += 1
                else:
                    tn += 1
            elif expected == "Partially":
                # Track separately; exclude from strict metrics
                if detected:
                    partial_tp += 1
                else:
                    partial_fp += 1

            # Unknown expected — skip

        precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if tp > 0 else 0.0)
        recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if tp > 0 else 0.0)
        f1 = 0.0
        if (precision + recall) > 0:
            f1 = 2 * precision * recall / (precision + recall)

        metrics[tool] = {
            "tp": tp,
            "fn": fn,
            "fp": fp,
            "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "strict_endpoints": tp + fn + fp + tn,
            "partial_tp": partial_tp,
            "partial_fp": partial_fp,
        }

    return metrics


def generate_report(endpoints_results, metrics, tool_versions, run_id, elapsed_total, tools_run):
    """Generate a human-readable console report."""
    lines = []
    lines.append("=" * 78)
    lines.append("  CROSS-TOOL XSS DETECTION COMPARISON REPORT")
    lines.append("=" * 78)
    lines.append(f"")
    lines.append(f"  Run ID:       {run_id}")
    lines.append(f"  Timestamp:    {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"  Total time:   {elapsed_total:.1f}s")
    lines.append(f"  Target:       {TARGET_URL}")
    lines.append(f"  Fuzzer:       {FUZZER_URL}")
    lines.append(f"  Tools run:    {', '.join(TOOL_LABELS[t] for t in tools_run)}")
    lines.append(f"")
    lines.append(f"  Tool Versions:")
    for tool, ver in tool_versions.items():
        lines.append(f"    {tool:15s} {ver}")
    lines.append(f"")

    # Ground truth summary
    vuln_count = sum(1 for r in endpoints_results if r["expected"] == "Vuln")
    safe_count = sum(1 for r in endpoints_results if r["expected"] == "Safe")
    partial_count = sum(1 for r in endpoints_results if r["expected"] == "Partially")
    lines.append(f"  Ground Truth: {vuln_count} vulnerable, {safe_count} safe, "
                 f"{partial_count} partially-safe endpoints")
    lines.append(f"")

    # Per-endpoint results
    lines.append("  " + "┌" + "─" * 75 + "┐")
    lines.append("  │ PER-ENDPOINT RESULTS" + " " * 52 + "│")
    lines.append("  ├" + "─" * 20 + "┬" + "─" * 8 + "┬" + "─" * 8 + "┬" + "─" * 8 + "┬" + "─" * 8 + "┬" + "─" * 8 + "┬" + "─" * 10 + "┤")
    lines.append("  │ Endpoint" + " " * 11 + "│ Expect │   RS   │   XS   │   DF   │  ZAP   │  Status  │")
    lines.append("  ├" + "─" * 20 + "┼" + "─" * 8 + "┼" + "─" * 8 + "┼" + "─" * 8 + "┼" + "─" * 8 + "┼" + "─" * 8 + "┼" + "─" * 10 + "┤")

    for ep in endpoints_results:
        name = ep["name"]
        exp = ep["expected"]
        exp_short = exp[:3]  # "Vul", "Saf", "Par"

        def tool_detected(t):
            r = ep["tool_results"].get(t, {})
            d = r.get("detected", False)
            return "✓" if d else "·"

        def status_str(ep):
            detections = {}
            for t in tools_run:
                detections[t] = ep["tool_results"].get(t, {}).get("detected", False)

            if exp == "Vuln":
                misses = sum(1 for t in tools_run if not detections[t])
                if misses == 0:
                    return " All found"
                elif misses == len(tools_run):
                    return " All missed"
                else:
                    return f" {misses} missed"
            elif exp == "Safe":
                fps = sum(1 for t in tools_run if detections[t])
                if fps == 0:
                    return "  No FPs"
                else:
                    return f" {fps} FP(s)"
            else:  # Partially
                return "Edge case"

        rs_det = tool_detected("red_sentinel")
        xs_det = tool_detected("xsstrike")
        df_det = tool_detected("dalfox")
        zp_det = tool_detected("zap")
        status = status_str(ep)

        lines.append(f"  │ {name:20s} │  {exp_short:4s} │   {rs_det}   │   {xs_det}   │   {df_det}   │   {zp_det}   │{status:9s}│")

    lines.append("  ├" + "─" * 20 + "┴" + "─" * 8 + "┴" + "─" * 8 + "┴" + "─" * 8 + "┴" + "─" * 8 + "┴" + "─" * 8 + "┴" + "─" * 10 + "┤")
    lines.append("  │  RS=Red Sentinel    XS=XSStrike    DF=Dalfox    ZAP=OWASP ZAP              │")
    lines.append("  │  ✓=Detected        ·=Not found                                           │")
    lines.append("  " + "└" + "─" * 75 + "┘")
    lines.append(f"")

    # Aggregate metrics per tool
    lines.append("  " + "┌" + "─" * 75 + "┐")
    lines.append("  │ AGGREGATE METRICS (strict: Vuln vs Safe only)" + " " * 19 + "│")
    lines.append("  ├" + "─" * 14 + "┬" + "─" * 6 + "┬" + "─" * 6 + "┬" + "─" * 6 + "┬" + "─" * 6 + "┬" + "─" * 10 + "┬" + "─" * 10 + "┬" + "─" * 11 + "┤")
    lines.append("  │ Tool" + " " * 10 + "│  TP  │  FN  │  FP  │  TN  │ Precision│  Recall  │    F1     │")
    lines.append("  ├" + "─" * 14 + "┼" + "─" * 6 + "┼" + "─" * 6 + "┼" + "─" * 6 + "┼" + "─" * 6 + "┼" + "─" * 10 + "┼" + "─" * 10 + "┼" + "─" * 11 + "┤")

    # Sort by F1 descending
    sorted_tools = sorted(tools_run, key=lambda t: metrics[t]["f1"], reverse=True)
    for tool in sorted_tools:
        m = metrics[tool]
        lines.append(f"  │ {TOOL_LABELS[tool]:12s} │ {m['tp']:4d} │ {m['fn']:4d} │ {m['fp']:4d} │ {m['tn']:4d} │   {m['precision']:.3f}  │   {m['recall']:.3f}  │  {m['f1']:.3f}   │")

    lines.append("  ├" + "─" * 14 + "┴" + "─" * 6 + "┴" + "─" * 6 + "┴" + "─" * 6 + "┴" + "─" * 6 + "┴" + "─" * 10 + "┴" + "─" * 10 + "┴" + "─" * 11 + "┤")

    # Per-category breakdown
    lines.append("  │ PER-CATEGORY BREAKDOWN (detected / total vuln endpoints)" + " " * 13 + "│")
    lines.append("  ├" + "─" * 14 + "┬" + "─" * 10 + "┬" + "─" * 10 + "┬" + "─" * 10 + "┬" + "─" * 10 + "┬" + "─" * 10 + "┤")
    lines.append("  │ Category" + " " * 6 + "│ Endpoints│     RS   │    XS    │    DF    │    ZAP   │")
    lines.append("  ├" + "─" * 14 + "┼" + "─" * 10 + "┼" + "─" * 10 + "┼" + "─" * 10 + "┼" + "─" * 10 + "┼" + "─" * 10 + "┤")

    categories = {}
    for ep in endpoints_results:
        cat = ep.get("category", "Other")
        categories.setdefault(cat, {"total": 0, "tools": {t: 0 for t in tools_run}})
        categories[cat]["total"] += 1
        for t in tools_run:
            if ep["tool_results"].get(t, {}).get("detected", False):
                categories[cat]["tools"][t] += 1

    for cat, data in sorted(categories.items()):
        total = data["total"]
        rs_count = data["tools"]["red_sentinel"]
        xs_count = data["tools"]["xsstrike"]
        df_count = data["tools"]["dalfox"]
        zp_count = data["tools"]["zap"]
        lines.append(f"  │ {cat:12s} │     {total:2d}/{total:2d}  │   {rs_count:2d}/{total:2d}  │   {xs_count:2d}/{total:2d}  │   {df_count:2d}/{total:2d}  │   {zp_count:2d}/{total:2d}  │")

    lines.append("  " + "└" + "─" * 14 + "┴" + "─" * 10 + "┴" + "─" * 10 + "┴" + "─" * 10 + "┴" + "─" * 10 + "┴" + "─" * 10 + "┘")
    lines.append(f"")

    # Partial/edge case results
    if partial_count > 0:
        lines.append("  Edge Cases (Partially-safe endpoints — excluded from strict metrics):")
        for ep in endpoints_results:
            if ep["expected"] == "Partially":
                detections = []
                for t in tools_run:
                    d = ep["tool_results"].get(t, {}).get("detected", False)
                    detections.append(f"{TOOL_LABELS[t]}: {'Vuln' if d else 'Safe'}")
                lines.append(f"    {ep['name']:25s} {' | '.join(detections)}")
        lines.append(f"")

    # Key findings
    lines.append("  Key Findings:")
    best_tool = max(sorted_tools, key=lambda t: metrics[t]["f1"])
    lines.append(f"    - Best F1: {TOOL_LABELS[best_tool]} ({metrics[best_tool]['f1']:.3f})")

    # FP analysis
    for tool in sorted_tools:
        m = metrics[tool]
        if m["fp"] > 0:
            fps = [ep["name"] for ep in endpoints_results
                   if ep["expected"] == "Safe"
                   and ep["tool_results"].get(tool, {}).get("detected", False)]
            lines.append(f"    - {TOOL_LABELS[tool]} FPs ({m['fp']}): {', '.join(fps)}")

    # FN analysis
    for tool in sorted_tools:
        m = metrics[tool]
        if m["fn"] > 0:
            fns = [ep["name"] for ep in endpoints_results
                   if ep["expected"] == "Vuln"
                   and not ep["tool_results"].get(tool, {}).get("detected", False)]
            lines.append(f"    - {TOOL_LABELS[tool]} FNs ({m['fn']}): {', '.join(fns)}")

    lines.append(f"")
    lines.append("=" * 78)

    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Clean, Reproducible Cross-Tool XSS Comparison Runner"
    )
    parser.add_argument("--limit", type=int, default=None,
                        help="Limit to first N endpoints")
    parser.add_argument("--output", type=str, default=None,
                        help="Custom output directory name")
    parser.add_argument("--skip", type=str, nargs="*", default=[],
                        choices=TOOLS,
                        help=f"Tools to skip: {', '.join(TOOLS)}")
    parser.add_argument("--resume", type=str, default=None,
                        help="Re-run report generation from saved results.json")
    args = parser.parse_args()

    # ── Determine tools to run ──
    tools_to_run = [t for t in TOOLS if t not in args.skip]

    # ── Resuming from saved data ──
    if args.resume:
        resume_path = Path(args.resume)
        if not resume_path.exists():
            print(f"[!] Resume file not found: {resume_path}")
            return 1

        saved = load_json(resume_path)
        endpoints_results = saved["per_endpoint_results"]
        tool_versions = saved.get("tool_versions", {})
        run_id = saved.get("run_id", "resumed")
        elapsed_total = saved.get("total_time_seconds", 0)
        ground_truth = saved.get("ground_truth", load_ground_truth())

        metrics = compute_metrics(endpoints_results, tools_to_run, ground_truth)
        report = generate_report(endpoints_results, metrics, tool_versions,
                                 run_id, elapsed_total, tools_to_run)
        print(report)
        return 0

    # ── Load data ──
    print("Loading ground truth and endpoint manifest...")
    ground_truth = load_ground_truth()
    manifest = load_manifest()
    all_endpoints = manifest.get("endpoints", [])

    if args.limit:
        all_endpoints = all_endpoints[:args.limit]

    # Verify ground truth coverage
    missing = [ep["name"] for ep in all_endpoints if ep["name"] not in ground_truth]
    if missing:
        print(f"  Warning: Endpoints missing from ground truth: {', '.join(missing)}")
        # Use manifest's expected as fallback
        for ep in all_endpoints:
            if ep["name"] not in ground_truth:
                ground_truth[ep["name"]] = ep.get("expected", "Unknown")

    # ── Capture tool versions ──
    print("Capturing tool versions...")
    tool_versions = get_tool_versions()
    for tool, ver in tool_versions.items():
        print(f"  {tool:15s} {ver}")

    # ── Create output dir ──
    run_id = args.output or datetime.now().strftime("comparison_%Y-%m-%d_%H-%M-%S")
    run_dir = OUTPUT_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # ── Run endpoints ──
    vuln_endpoints = [ep for ep in all_endpoints if ground_truth.get(ep["name"]) == "Vuln"]
    safe_endpoints = [ep for ep in all_endpoints if ground_truth.get(ep["name"]) == "Safe"]
    partial_endpoints = [ep for ep in all_endpoints if ground_truth.get(ep["name"]) == "Partially"]

    print(f"\nRunning {len(tools_to_run)} tools against {len(all_endpoints)} endpoints:")
    print(f"  Vulnerable:   {len(vuln_endpoints)}")
    print(f"  Safe:         {len(safe_endpoints)}")
    print(f"  Edge cases:   {len(partial_endpoints)}")
    print(f"  Tools:        {', '.join(TOOL_LABELS[t] for t in tools_to_run)}")
    print()

    endpoints_results = []
    total_start = time.time()

    for idx, ep in enumerate(all_endpoints, 1):
        name = ep["name"]
        exp = ground_truth.get(name, "Unknown")
        print(f"  [{idx}/{len(all_endpoints)}] {name} ({exp})...")

        result = run_endpoint(ep, tools_to_run, ground_truth)
        endpoints_results.append(result)

        # Print per-tool summary line
        summary_parts = []
        for t in tools_to_run:
            r = result["tool_results"][t]
            d = "✓" if r.get("detected") else "·"
            err = r.get("error", "")
            if err:
                d = f"x{err[:30]}"
            summary_parts.append(f"{TOOL_LABELS[t][:12]}:{d}")
        print(f"    {' | '.join(summary_parts)}")

    elapsed_total = time.time() - total_start

    # ── Compute metrics ──
    metrics = compute_metrics(endpoints_results, tools_to_run, ground_truth)

    # ── Generate report ──
    report = generate_report(endpoints_results, metrics, tool_versions,
                             run_id, elapsed_total, tools_to_run)
    print()
    print(report)

    # ── Save output files ──
    # 1. Meta (run metadata)
    meta = {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_url": TARGET_URL,
        "fuzzer_url": FUZZER_URL,
        "tools_run": tools_to_run,
        "tool_versions": tool_versions,
        "total_endpoints": len(all_endpoints),
        "total_time_seconds": round(elapsed_total, 2),
        "ground_truth_path": str(GROUND_TRUTH_PATH),
        "manifest_path": str(MANIFEST_PATH),
    }
    (run_dir / "_meta.json").write_text(json.dumps(meta, indent=2))

    # 2. Frozen ground truth
    gt_data = load_json(GROUND_TRUTH_PATH)
    (run_dir / "ground_truth.json").write_text(json.dumps(gt_data, indent=2))

    # 3. Frozen manifest
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    # 4. Per-endpoint results (clean, no raw output)
    clean_results = []
    for ep in endpoints_results:
        clean_ep = {
            "name": ep["name"],
            "category": ep["category"],
            "url": ep["url"],
            "params": ep["params"],
            "expected": ep["expected"],
            "tool_results": {},
        }
        for t in tools_to_run:
            r = ep["tool_results"][t]
            clean_ep["tool_results"][t] = {
                "detected": r["detected"],
                "details": r.get("details", []),
                "time_seconds": r.get("time_seconds", 0),
                "error": r.get("error"),
            }
            # Add tool-specific metrics
            if t == "red_sentinel":
                clean_ep["tool_results"][t]["vuln_count"] = r.get("vuln_count", 0)
                clean_ep["tool_results"][t]["executed_count"] = r.get("executed_count", 0)
                clean_ep["tool_results"][t]["reflected_count"] = r.get("reflected_count", 0)
            elif t == "xsstrike":
                clean_ep["tool_results"][t]["payloads_found"] = r.get("payloads_found", 0)
                clean_ep["tool_results"][t]["reflection_count"] = r.get("reflection_count", 0)
            elif t == "dalfox":
                clean_ep["tool_results"][t]["poc_count"] = r.get("poc_count", 0)
            elif t == "zap":
                clean_ep["tool_results"][t]["total_alerts"] = r.get("total_alerts", 0)
                clean_ep["tool_results"][t]["xss_alerts"] = r.get("xss_alerts", [])
                clean_ep["tool_results"][t]["alert_type_counts"] = r.get("alert_type_counts", {})

        clean_results.append(clean_ep)

    (run_dir / "per_endpoint.json").write_text(json.dumps(clean_results, indent=2))

    # 5. Aggregate metrics
    (run_dir / "aggregate.json").write_text(json.dumps(metrics, indent=2))

    # 6. Report (human-readable)
    (run_dir / "report.txt").write_text(report)

    # 7. Combined results file (for --resume)
    combined = {
        "run_id": run_id,
        "total_time_seconds": round(elapsed_total, 2),
        "tool_versions": tool_versions,
        "ground_truth": ground_truth,
        "per_endpoint_results": clean_results,
        "metrics": metrics,
    }
    (run_dir / "results.json").write_text(json.dumps(combined, indent=2))

    print(f"\n  Results saved to: {run_dir}")
    print(f"     _meta.json         - run metadata")
    print(f"     ground_truth.json  - frozen ground truth")
    print(f"     manifest.json      - frozen endpoint manifest")
    print(f"     per_endpoint.json  - per-endpoint per-tool results")
    print(f"     aggregate.json     - aggregate TP/FP/FN/TN per tool")
    print(f"     report.txt         - human-readable report")
    print(f"     results.json       - all data (for --resume)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
