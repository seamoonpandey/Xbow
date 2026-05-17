#!/usr/bin/env python3
"""
eval/run.py — Reproducible Evaluation Runner

Reads endpoint manifests from eval/manifests/, runs each against the fuzzer,
and saves all raw results + frozen manifests into a timestamped archive directory.

Supports multi-target evaluation against real-world apps like OWASP Juice Shop,
OWASP WebGoat, and OWASP Benchmark.

Usage:
    python3 eval/run.py                              # full eval (all manifests)
    python3 eval/run.py --manifest reflected         # single manifest
    python3 eval/run.py --target juice-shop          # target from registry
    python3 eval/run.py --limit 5                    # first N endpoints
    python3 eval/run.py --output my-run              # custom archive dir name
    python3 eval/run.py --target help                # list available targets

Output structure:
    eval/archive/<run_id>/
        _meta.json               # Run metadata (timestamp, args, target info)
        manifest_frozen.json     # Combined frozen copy of all endpoints used
        results/                 # Per-endpoint raw results
            <endpoint-name>.json
            raw_responses/       # Full fuzzer response dumps
                <endpoint-name>.json
        summary.json             # Aggregated per-endpoint summary with metrics
        portswigger.json         # PortSwigger coverage results (if run)
"""

import csv
import json
import os
import re
import sys
import time
import ssl
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFESTS_DIR = ROOT / "eval" / "manifests"
ARCHIVE_DIR = ROOT / "eval" / "archive"
TARGETS_REGISTRY = ROOT / "eval" / "targets" / "_targets.json"
TARGETS_DIR = ROOT / "eval" / "targets"

CONTEXT = os.environ.get("CONTEXT_URL", "http://localhost:5001")
PAYLOAD = os.environ.get("PAYLOAD_URL", "http://localhost:5002")
FUZZER = os.environ.get("FUZZER_URL", "http://localhost:5003")
TARGET = os.environ.get("TARGET_URL", "http://localhost:9090")
TARGET_LEGACY = os.environ.get("TARGET_LEGACY_URL", "http://localhost:8081")
TARGET_NAME = "exploitable"  # tracking which target is active


# ── Target Registry ─────────────────────────────────────────────

def list_targets():
    """Print available evaluation targets from the registry."""
    if not TARGETS_REGISTRY.exists():
        print("[!] Target registry not found")
        return

    with open(TARGETS_REGISTRY) as f:
        registry = json.load(f)

    print("\nAvailable evaluation targets:")
    print(f"{'─'*70}")
    for t in registry.get("targets", []):
        name = t["name"]
        label = t["label"]
        desc = t.get("description", "")
        url = t.get("default_url", "")
        auth = "🔐" if t.get("auth_required") else "  "
        print(f"  {name:20s} {auth} {label}")
        print(f"  {'':20s}   {url}")
        print(f"  {'':20s}   {desc[:80]}")
        print()
    print("Usage: python3 eval/run.py --target <name>")


def load_target_config(target_name):
    """Load a target configuration from the registry by name.

    Returns dict with 'url', 'label', 'config_path', 'auth_required', etc.,
    or None if not found.
    """
    if not TARGETS_REGISTRY.exists():
        return None
    with open(TARGETS_REGISTRY) as f:
        registry = json.load(f)
    for t in registry.get("targets", []):
        if t["name"] == target_name:
            return {
                "url": t.get("default_url", ""),
                "label": t.get("label", target_name),
                "config_path": t.get("config_path"),
                "auth_required": t.get("auth_required", False),
                "auth_config": t.get("auth_config"),
                "docker_image": t.get("docker_image"),
                "port": t.get("port"),
                "category": t.get("category", "unknown"),
                "protocol": t.get("protocol", "http"),
                "tls_verify": t.get("tls_verify", True),
            }
    return None


def load_target_endpoints(config_path):
    """Load endpoint definitions from a target config JSON file.

    Returns a list of endpoint dicts with placeholder URLs resolved.
    """
    cfg_file = ROOT / config_path
    if not cfg_file.exists():
        print(f"  [!] Target config not found: {cfg_file}")
        return []

    with open(cfg_file) as f:
        data = json.load(f)

    meta_target_url = data.get("_meta", {}).get("target_url", "")
    endpoints = data.get("endpoints", [])

    for ep in endpoints:
        # Resolve target URL if endpoint has a relative placeholder
        if "{TARGET}" in ep.get("url", ""):
            ep["url"] = ep["url"].replace("{TARGET}", meta_target_url or TARGET)
        if ep.get("display_url") and "{TARGET}" in ep["display_url"]:
            ep["display_url"] = ep["display_url"].replace("{TARGET}", meta_target_url or TARGET)

    print(f"  Loaded {len(endpoints)} endpoints from {config_path}")
    return endpoints


# ── API Helpers ─────────────────────────────────────────────────
def _get_ssl_context():
    """Create SSL context that disables verification for self-signed certs."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def api_post(base, endpoint, data, timeout=120, tls_verify=True):
    """POST JSON to an API endpoint and return parsed response."""
    url = f"{base}{endpoint}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        context = _get_ssl_context() if not tls_verify else None
        resp = urllib.request.urlopen(req, timeout=timeout, context=context)
        return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f"HTTP {e.code}: {body[:300]}") from e


def make_payload(payload_str, param):
    """Create a standardized FuzzPayload dict."""
    return {
        "payload": payload_str,
        "target_param": param,
        "confidence": 1.0,
        "technique": "original",
        "severity": "medium",
    }


def resolve_url(url):
    """Resolve {TARGET} and {TARGET_LEGACY} placeholders."""
    return url.replace("{TARGET}", TARGET).replace("{TARGET_LEGACY}", TARGET_LEGACY)


# ── Manifest Loading ────────────────────────────────────────────

def load_manifests(manifest_filter=None):
    """Load all JSON manifests from the manifests directory."""
    if not MANIFESTS_DIR.exists():
        print(f"[!] Manifests directory not found: {MANIFESTS_DIR}")
        sys.exit(1)

    all_endpoints = []
    meta = {}

    for mf_path in sorted(MANIFESTS_DIR.glob("*.json")):
        mf_name = mf_path.stem
        if mf_name == "portswigger":
            continue
        if manifest_filter and manifest_filter != mf_name:
            continue

        with open(mf_path, "r") as f:
            data = json.load(f)

        meta[mf_name] = data.get("_meta", {})

        for ep in data.get("endpoints", []):
            ep["url"] = resolve_url(ep["url"])
            if ep.get("display_url"):
                ep["display_url"] = resolve_url(ep["display_url"])
            all_endpoints.append(ep)

    print(f"  Loaded {len(all_endpoints)} endpoints from {len(meta)} manifests")
    for mf_name, m in sorted(meta.items()):
        cat_count = sum(1 for e in all_endpoints if e.get("category", "").lower() == m.get("category", "").lower())
        print(f"    {mf_name}: {cat_count} endpoints")

    return all_endpoints


def load_portswigger_manifest():
    """Load the PortSwigger manifest with context routing configuration."""
    mf_path = MANIFESTS_DIR / "portswigger.json"
    if not mf_path.exists():
        return None
    with open(mf_path, "r") as f:
        return json.load(f)


# ── Target-Specific Helpers ─────────────────────────────────────

def attempt_target_auth(target_config):
    """Attempt authentication for targets that require it (e.g., WebGoat)."""
    if not target_config or not target_config.get("auth_required"):
        return None

    auth = target_config.get("auth_config")
    if not auth:
        return None

    login_url = f"{TARGET}{auth['endpoint']}"
    method = auth.get("method", "POST")
    creds = auth.get("credentials", {})
    fields_map = auth.get("fields", {})
    session_cookie = auth.get("session_cookie")

    try:
        # Build login payload using field mappings
        login_payload = {}
        for mapped_field, cred_field in fields_map.items():
            login_payload[mapped_field] = creds.get(cred_field, "")

        req = urllib.request.Request(
            login_url,
            data=urllib.parse.urlencode(login_payload).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method=method,
        )
        resp = urllib.request.urlopen(req, timeout=30)

        # Extract session cookie from response headers
        cookies = resp.headers.get_all("Set-Cookie") or []
        for c in cookies:
            if session_cookie in c:
                # Extract the cookie value
                match = re.search(rf"{session_cookie}=([^;]+)", c)
                if match:
                    print(f"  ✅ Authenticated to {target_config['label']} (session: {match.group(1)[:16]}...)")
                    return match.group(1)

        print(f"  ⚠️  Auth response but no {session_cookie} cookie found")
        return None

    except Exception as e:
        print(f"  ⚠️  Auth failed for {target_config['label']}: {str(e)[:80]}")
        return None


# ── Endpoint Runner ─────────────────────────────────────────────

def run_endpoint(endpoint, fuzzer_url, session_cookie=None):
    """Run a single endpoint through the fuzzer."""
    payloads = [
        make_payload(p["payload"], p["target_param"])
        for p in endpoint.get("payloads", [])
    ]

    fuzz_request = {
        "url": endpoint["url"],
        "payloads": payloads,
        "verify_execution": True,
        "timeout": 60000,
    }

    if endpoint.get("stored_mode"):
        fuzz_request["stored_mode"] = True
        fuzz_request["display_url"] = endpoint.get("display_url", endpoint["url"])
        fuzz_request["form_fields"] = endpoint.get("form_fields", {})
    else:
        fuzz_request["stored_mode"] = False

    # Attach session cookie for authenticated targets
    if session_cookie:
        fuzz_request["cookies"] = {endpoint.get("auth_cookie_name", "JSESSIONID"): session_cookie}

    # Pass TLS config for HTTPS targets
    target_tls_verify = TLS_VERIFY
    if not target_tls_verify:
        fuzz_request["tls_verify"] = False

    start = time.time()
    try:
        fuzz_result = api_post(fuzzer_url, "/fuzz", fuzz_request, timeout=120)
        elapsed = time.time() - start

        results_list = fuzz_result.get("results", [])
        vuln_count = sum(1 for r in results_list if r.get("vuln"))
        executed_count = sum(1 for r in results_list if r.get("executed"))
        reflected_count = sum(1 for r in results_list if r.get("reflected"))

        vuln_details = []
        for vr in results_list:
            if vr.get("vuln"):
                ev = vr.get("evidence", {})
                vuln_details.append({
                    "payload": vr.get("payload", "")[:120],
                    "param": vr.get("target_param", ""),
                    "type": vr.get("type", ""),
                    "position": ev.get("reflection_position", ""),
                    "executed": vr.get("executed", False),
                    "exact": ev.get("exact_match", False),
                })

        return {
            "name": endpoint["name"],
            "category": endpoint.get("category", "Other"),
            "url": endpoint["url"],
            "expected": endpoint.get("expected", "Vuln"),
            "time": round(elapsed, 2),
            "total_payloads": len(payloads),
            "total_results": len(results_list),
            "reflected": reflected_count,
            "executed": executed_count,
            "vulns": vuln_count,
            "vuln_details": vuln_details,
            "status": "ok",
            "error": None,
            "raw_fuzzer_response": fuzz_result,
        }

    except Exception as e:
        elapsed = time.time() - start
        return {
            "name": endpoint["name"],
            "category": endpoint.get("category", "Other"),
            "url": endpoint["url"],
            "expected": endpoint.get("expected", "Vuln"),
            "time": round(elapsed, 2),
            "total_payloads": len(payloads),
            "total_results": 0,
            "reflected": 0,
            "executed": 0,
            "vulns": 0,
            "vuln_details": [],
            "status": "error",
            "error": str(e),
            "raw_fuzzer_response": None,
        }


# ── PortSwigger Runner ──────────────────────────────────────────

def run_portswigger(port_manifest):
    """Run PortSwigger payloads through multi-context routing."""
    if not port_manifest:
        print("  [!] No PortSwigger manifest found — skipping")
        return None

    meta = port_manifest.get("_meta", {})
    port_file = ROOT / meta.get("portswigger_file", "dataset/processed/portswigger_payloads.csv")
    sample_size = meta.get("sample_size", 50)
    context_routes = meta.get("context_routes", {})

    if not port_file.exists():
        print(f"  [!] PortSwigger CSV not found: {port_file} — skipping")
        return None

    all_payloads = []
    with open(port_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            p = row.get("payload", "").strip().strip('"')
            ctx = row.get("context", "unknown")
            if p:
                all_payloads.append((p, ctx))

    total = len(all_payloads)
    sample = all_payloads[:sample_size]

    print(f"\n  PortSwigger: {total} total, testing {sample_size} sample")

    default_route = {"url": "/reflected/body", "param": "q"}
    endpoint_batches = {}
    for p, ctx in sample:
        route = context_routes.get(ctx, default_route)
        if ctx == "attribute" and p.strip().startswith("<"):
            route = {"url": "/reflected/body", "param": "q"}
        full_url = f"{TARGET}{route['url']}"
        key = (full_url, route["param"])
        endpoint_batches.setdefault(key, []).append((p, ctx))

    print(f"  Routing to {len(endpoint_batches)} endpoint+param combinations")

    results = []
    detected = 0
    executed = 0
    per_context_stats = {}

    batch_count = sum((len(entries) + 4) // 5 for entries in endpoint_batches.values())
    batch_idx = 0

    for (url, param), payloads_list in sorted(endpoint_batches.items(), key=lambda x: -len(x[1])):
        endpoint_name = url.split("/")[-1]
        print(f"    → {endpoint_name}/{param} ({len(payloads_list)} payloads)")

        for i in range(0, len(payloads_list), 5):
            batch = payloads_list[i:i+5]
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
                    if vuln:
                        detected += 1
                    if exec_:
                        executed += 1
                    results.append({
                        "payload": r.get("payload", "")[:100],
                        "vuln": vuln,
                        "executed": exec_,
                        "reflected": r.get("reflected", False),
                        "type": r.get("type", ""),
                        "tested_on": f"{url}?{param}=<payload>",
                    })

                batch_detected = sum(1 for r in fuzz_result.get("results", []) if r.get("vuln"))
                print(f"      Batch {batch_idx}/{batch_count}: {len(batch)} payloads, detected: {batch_detected}")

            except Exception as e:
                print(f"      Batch {batch_idx}/{batch_count} error: {str(e)[:80]}")

    for ctx in set(c for _, c in sample):
        ctx_total = sum(1 for _, c in sample if c == ctx)
        ctx_detected = sum(1 for r in results if r["payload"][:100] in [p[:100] for p, c in sample if c == ctx and r["vuln"]])
        ctx_executed = sum(1 for r in results if r["payload"][:100] in [p[:100] for p, c in sample if c == ctx and r["executed"]])
        per_context_stats[ctx] = {
            "total": ctx_total,
            "detected": ctx_detected,
            "executed": ctx_executed,
            "coverage_pct": round(ctx_detected / ctx_total * 100, 1) if ctx_total else 0,
        }

    coverage_pct = round(detected / len(sample) * 100, 1) if sample else 0
    execution_pct = round(executed / len(sample) * 100, 1) if sample else 0

    return {
        "total_portswigger_payloads": total,
        "sample_tested": sample_size,
        "detected": detected,
        "browser_executed": executed,
        "coverage_pct": coverage_pct,
        "execution_pct": execution_pct,
        "context_breakdown": per_context_stats,
        "details": results,
    }


# ── Metrics ─────────────────────────────────────────────────────

def compute_metrics(endpoint_results):
    """Compute precision/recall/F1 from endpoint results."""
    tp = sum(1 for r in endpoint_results.values()
             if r.get("expected") == "Vuln" and r.get("vulns", 0) > 0)
    fn = sum(1 for r in endpoint_results.values()
             if r.get("expected") == "Vuln" and r.get("vulns", 0) == 0 and not r.get("error"))
    tn = sum(1 for r in endpoint_results.values()
             if r.get("expected") == "Safe" and r.get("vulns", 0) == 0)
    fp = sum(1 for r in endpoint_results.values()
             if r.get("expected") == "Safe" and r.get("vulns", 0) > 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    categories = {}
    for name, r in endpoint_results.items():
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

    return {
        "tp": tp, "fn": fn, "tn": tn, "fp": fp,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "total_endpoints": len(endpoint_results),
        "total_vulns": sum(r.get("vulns", 0) for r in endpoint_results.values()),
        "total_executed": sum(r.get("executed", 0) for r in endpoint_results.values()),
        "total_reflected": sum(r.get("reflected", 0) for r in endpoint_results.values()),
        "endpoints_with_errors": sum(1 for r in endpoint_results.values() if r.get("error")),
        "categories": categories,
    }


# ── Archive ─────────────────────────────────────────────────────

def save_archive(endpoint_results, portswigger_results, endpoints, run_id=None, target_name=None):
    """Save results and frozen manifests to a timestamped archive directory."""
    timestamp = datetime.utcnow().isoformat()
    run_id = run_id or datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = ARCHIVE_DIR / run_id
    results_dir = run_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "run_id": run_id,
        "timestamp": timestamp,
        "target": TARGET,
        "target_name": target_name or TARGET_NAME,
        "target_url": TARGET,
        "fuzzer": FUZZER,
        "context": CONTEXT,
        "payload": PAYLOAD,
        "endpoints_count": len(endpoint_results),
        "python_version": sys.version,
    }
    (run_dir / "_meta.json").write_text(json.dumps(meta, indent=2))

    summary_dict = {}
    for name, r in endpoint_results.items():
        per_ep = {k: v for k, v in r.items() if k != "raw_fuzzer_response"}
        (results_dir / f"{name}.json").write_text(json.dumps(per_ep, indent=2, default=str))

        raw_response = r.get("raw_fuzzer_response")
        if raw_response:
            raw_dir = results_dir / "raw_responses"
            raw_dir.mkdir(exist_ok=True)
            (raw_dir / f"{name}.json").write_text(json.dumps(raw_response, indent=2, default=str))

        summary_dict[name] = {
            "category": r["category"],
            "url": r["url"],
            "expected": r["expected"],
            "time": r["time"],
            "total_payloads": r["total_payloads"],
            "total_results": r["total_results"],
            "reflected": r["reflected"],
            "executed": r["executed"],
            "vulns": r["vulns"],
            "vuln_details": r["vuln_details"],
            "status": r["status"],
            "error": r["error"],
        }

    combined = {
        "_meta": meta,
        "endpoints": summary_dict,
        "metrics": compute_metrics(summary_dict),
        "portswigger": portswigger_results,
    }
    (run_dir / "summary.json").write_text(json.dumps(combined, indent=2, default=str))

    if portswigger_results:
        (run_dir / "portswigger.json").write_text(json.dumps(portswigger_results, indent=2, default=str))

    (run_dir / "manifest_frozen.json").write_text(json.dumps(endpoints, indent=2, default=str))

    return run_dir


# ── CLI ─────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Red Sentinel Reproducible Evaluation Runner")
    parser.add_argument("--manifest", type=str, default=None,
                        help="Run only a specific manifest (e.g., 'reflected')")
    parser.add_argument("--limit", type=int, default=None,
                        help="Limit to first N endpoints")
    parser.add_argument("--output", type=str, default=None,
                        help="Custom archive directory name (default: timestamp)")
    parser.add_argument("--skip-portswigger", action="store_true",
                        help="Skip PortSwigger coverage analysis")
    parser.add_argument("--fuzzer", type=str, default=None,
                        help="Fuzzer URL override (default: FUZZER_URL env or http://localhost:5003)")
    parser.add_argument("--target", type=str, default=None,
                        help="Target name from registry (e.g., 'juice-shop', 'webgoat', 'owasp-benchmark'). Use '--target help' to list.")
    parser.add_argument("--target-url", type=str, default=None,
                        help="Direct target URL override (bypasses registry)")
    parser.add_argument("--list-manifests", action="store_true",
                        help="List available manifests and exit")

    args = parser.parse_args()

    # ── Handle help and listing ──
    if args.target == "help" or args.list_manifests:
        list_targets()
        print("\nAvailable manifests:")
        for mf_path in sorted(MANIFESTS_DIR.glob("*.json")):
            with open(mf_path) as f:
                data = json.load(f)
            ep_count = len(data.get("endpoints", []))
            desc = data.get("_meta", {}).get("description", "")[:60]
            print(f"  {mf_path.stem:25s} {ep_count:3d} endpoints  ({desc})")
        return 0

    # ── Configure target ──
    global FUZZER, TARGET, TARGET_LEGACY, TARGET_NAME, TLS_VERIFY
    TLS_VERIFY = True
    if args.fuzzer:
        FUZZER = args.fuzzer

    target_config = None
    if args.target_url:
        TARGET = args.target_url
        TARGET_LEGACY = args.target_url
        TARGET_NAME = "custom"
    elif args.target:
        target_config = load_target_config(args.target)
        if target_config:
            TARGET = target_config["url"]
            TARGET_LEGACY = target_config["url"]
            TARGET_NAME = args.target
            TLS_VERIFY = target_config.get("tls_verify", True)
        else:
            print(f"[!] Unknown target '{args.target}'. Use --target help to list.")
            return 1

    # ── Load endpoints ──
    print(f"Red Sentinel Reproducible Evaluation Runner")
    print(f"{'='*60}")
    print(f"  Target:    {TARGET_NAME} ({TARGET})")
    print(f"  Fuzzer:    {FUZZER}")
    print(f"  Manifests: {MANIFESTS_DIR}")
    print(f"  Archive:   {ARCHIVE_DIR}")
    print(f"{'='*60}\n")

    # Load target-specific endpoints first (if any)
    target_endpoints = []
    if target_config and target_config.get("config_path"):
        target_endpoints = load_target_endpoints(target_config["config_path"])

    # Then load manifest endpoints
    manifest_endpoints = load_manifests(args.manifest)

    # Combine: target endpoints first, then manifest endpoints
    all_endpoints = target_endpoints + manifest_endpoints

    if not all_endpoints:
        print("[!] No endpoints loaded. Check target name or manifest filter.")
        return 1

    if args.limit:
        all_endpoints = all_endpoints[:args.limit]
        print(f"  (Limited to first {args.limit} endpoints)")

    total_payloads = sum(len(e.get("payloads", [])) for e in all_endpoints)
    print(f"\n  Total: {len(all_endpoints)} endpoints, {total_payloads} payloads\n")

    # ── Authenticate (if needed) ──
    session_cookie = None
    if target_config and target_config.get("auth_required"):
        print(f"  🔐 Target requires authentication — attempting login...")
        session_cookie = attempt_target_auth(target_config)

    # ── Check connectivity ──
    try:
        api_post(FUZZER, "/fuzz", {
            "url": TARGET + "/health",
            "payloads": [make_payload("test", "q")],
            "verify_execution": False,
            "timeout": 5000,
            "stored_mode": False,
        })
        print(f"  ✅ Fuzzer reachable at {FUZZER}")
    except Exception:
        print(f"  ⚠️  Fuzzer at {FUZZER} not reachable — will retry per endpoint\n")

    # ── Run endpoints ──
    print(f"\n{'='*60}")
    print(f"  RUNNING ENDPOINTS")
    print(f"{'='*60}")

    endpoint_results = {}
    for idx, ep in enumerate(all_endpoints, 1):
        ep_name = ep["name"]
        if not ep.get("payloads"):
            print(f"  [{idx}/{len(all_endpoints)}] {ep_name} (SKIP — no payloads)")
            continue

        print(f"\n  [{idx}/{len(all_endpoints)}] {ep_name} ({ep.get('category', '?')})")
        print(f"      URL: {ep['url']}")
        print(f"      Payloads: {len(ep['payloads'])}")

        result = run_endpoint(ep, FUZZER, session_cookie=session_cookie)
        endpoint_results[ep_name] = result

        if result["status"] == "ok":
            print(f"      Time: {result['time']:.2f}s | Results: {result['total_results']} | "
                  f"Reflected: {result['reflected']} | Executed: {result['executed']} | Vulns: {result['vulns']}")
        else:
            print(f"      Error: {result['error'][:100]}")    # ── Run PortSwigger ──
    portswigger_results = None
    should_run_portswigger = not args.skip_portswigger
    if target_config and target_config.get("category") in ("real-world", "benchmark"):
        # PortSwigger routing uses exploitable-specific endpoints (e.g., /reflected/body)
        print(f"\n  ⏭️  Skipping PortSwigger coverage for {TARGET_NAME} (uses exploitable-specific endpoint routing)")
        should_run_portswigger = False
    if should_run_portswigger:
        print(f"\n{'='*60}")
        print(f"  RUNNING PORTSWIGGER COVERAGE")
        print(f"{'='*60}")
        port_manifest = load_portswigger_manifest()
        portswigger_results = run_portswigger(port_manifest)
        if portswigger_results:
            print(f"\n  PortSwigger Coverage: {portswigger_results['coverage_pct']}% "
                  f"({portswigger_results['detected']}/{portswigger_results['sample_tested']})")
            print(f"  Browser-Confirmed: {portswigger_results['execution_pct']}%")

    # ── Compute metrics ──
    metrics = compute_metrics(endpoint_results)

    print(f"\n{'='*60}")
    print(f"  RESULTS SUMMARY — {TARGET_NAME}")
    print(f"{'='*60}")
    print(f"  Endpoints: {metrics['total_endpoints']}")
    print(f"  Vulnerabilities: {metrics['total_vulns']} (browser-confirmed: {metrics['total_executed']})")
    print(f"  TP={metrics['tp']}, FN={metrics['fn']}, TN={metrics['tn']}, FP={metrics['fp']}")
    print(f"  Precision: {metrics['precision']:.3f}")
    print(f"  Recall:    {metrics['recall']:.3f}")
    print(f"  F1-score:  {metrics['f1']:.3f}")
    if portswigger_results:
        print(f"  PortSwigger Coverage: {portswigger_results['coverage_pct']}%")
    print(f"  Endpoints with errors: {metrics['endpoints_with_errors']}")

    # ── Save archive ──
    run_dir = save_archive(endpoint_results, portswigger_results, all_endpoints,
                           run_id=args.output, target_name=TARGET_NAME)
    print(f"\n  ✅ Results saved to: {run_dir}")
    print(f"     summary.json — aggregated results")
    print(f"     results/      — per-endpoint raw results")
    print(f"     manifest_frozen.json — frozen endpoint definitions")

    print(f"\n  Next steps:")
    print(f"     python3 eval/analysis/metrics.py {run_dir.name}")
    print(f"     python3 eval/analysis/fn_analysis.py {run_dir.name}")
    print(f"     python3 eval/reports/report_md.py {run_dir.name}")
    print(f"     python3 eval/reports/report_html.py {run_dir.name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
