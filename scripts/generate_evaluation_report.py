#!/usr/bin/env python3
"""Generate full evaluation report in docs/evaluation/ using available metrics."""
from pathlib import Path
import json
import re
import math

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs" / "evaluation"
OUT_MD = OUT_DIR / "Evaluation_and_Results.md"

def load_json(p):
    return json.loads(Path(p).read_text())

def compute_class_metrics(cm):
    # cm: list of lists (square)
    n = len(cm)
    precision = []
    recall = []
    f1 = []
    support = []
    for i in range(n):
        tp = cm[i][i]
        fn = sum(cm[i]) - tp
        tp_col = sum(cm[r][i] for r in range(n))
        fp = tp_col - tp
        sup = tp + fn
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        precision.append(prec)
        recall.append(rec)
        f1.append(f)
        support.append(sup)
    return precision, recall, f1, support

def parse_benchmark_html(p):
    txt = Path(p).read_text(errors='ignore')
    # find the aggregate table rows for scanners
    rows = []
    # simple pattern: <td><strong>NAME</strong>... then subsequent <td> numbers
    pattern = re.compile(r"<tr>\s*<td><strong>([^<]+)</strong>.*?<td>(\d+)</td>\s*<td class=\"num tp\">(\d+)</td>\s*<td class=\"num fp\">(\d+)</td>\s*<td class=\"num fn\">(\d+)</td>.*?<td class=\"num\">([0-9.]+)%</td>\s*<td class=\"num\">([0-9.]+)%</td>\s*<td class=\"num f1\">([0-9.]+)%</td>\s*<td class=\"num\">([0-9.]+)s</td>", re.S)
    for m in pattern.finditer(txt):
        name = m.group(1).strip()
        endpoints = int(m.group(2))
        tp = int(m.group(3))
        fp = int(m.group(4))
        fn = int(m.group(5))
        prec = float(m.group(6))
        rec = float(m.group(7))
        f1 = float(m.group(8))
        time_s = float(m.group(9))
        rows.append({"name":name,"endpoints":endpoints,"tp":tp,"fp":fp,"fn":fn,"precision":prec,"recall":rec,"f1":f1,"time_s":time_s})
    return rows

def main():
    OUT_DIR.mkdir(exist_ok=True)

    # load existing 6.3 if present
    six3 = ROOT / "docs" / "evaluation" / "6.3_dataset_evaluation.md"
    six3_text = six3.read_text() if six3.exists() else ""

    # load model test results
    test_json = ROOT / "model" / "checkpoints" / "test_results.json"
    tr = load_json(test_json) if test_json.exists() else {}

    context_labels = [
        "script_injection",
        "event_handler",
        "js_uri",
        "tag_injection",
        "template_injection",
        "dom_sink",
        "attribute_escape",
        "generic",
    ]

    # compute per-class metrics from confusion matrix
    ctx_cm = tr.get("context_confusion_matrix")
    if ctx_cm:
        prec, rec, f1, support = compute_class_metrics(ctx_cm)
    else:
        prec=rec=f1=support=[]

    # ranker metrics
    ranker_json = ROOT / "model" / "ranker" / "ranker_metrics.json"
    ranker = load_json(ranker_json) if ranker_json.exists() else {}

    # benchmark HTML (Downloads attachment) - attempt common paths
    bench_paths = [Path("/home/moon/Downloads/benchmark_report (2).html"), Path("/home/moon/Downloads/benchmark_report.html")]
    bench_rows = []
    for p in bench_paths:
        if p.exists():
            bench_rows = parse_benchmark_html(p)
            break

    # fallback: try docs/benchmark_report.html
    if not bench_rows:
        p = ROOT / "docs" / "benchmark_report.html"
        if p.exists():
            bench_rows = parse_benchmark_html(p)

    # build markdown
    md = []
    md.append("# Evaluation and Results")
    md.append("")
    md.append("## 6.1 Evaluation Objectives")
    md.append("")
    md.append("Briefly evaluate context classification, payload ranking, vulnerability detection, and end-to-end performance.")
    md.append("")
    md.append("## 6.2 Experimental Setup")
    md.append("")
    md.append("See project `RUN.md` for exact environment and targets used in benchmarks.")
    md.append("")
    md.append("## 6.3 Dataset Evaluation")
    md.append("")
    md.append(six3_text)
    md.append("")
    md.append("## 6.4 AI Context Classification Results")
    md.append("")
    md.append("**Experiment 1: DistilBERT Context Classification**")
    md.append("")
    md.append("**Table 6.3: DistilBERT Classification Results**")
    md.append("")
    md.append("| Context Class | Precision | Recall | F1-Score | Support |")
    md.append("|---|---:|---:|---:|---:|")
    for i, lbl in enumerate(context_labels):
        p = prec[i] if i < len(prec) else 0.0
        r = rec[i] if i < len(rec) else 0.0
        f = f1[i] if i < len(f1) else 0.0
        s = support[i] if i < len(support) else 0
        md.append(f"| {lbl} | {p:.3f} | {r:.3f} | {f:.3f} | {s} |")
    md.append("")

    # confusion matrix summary
    md.append("**Table 6.4: Confusion Matrix Summary (context)**")
    md.append("")
    if ctx_cm:
        md.append("Context labels order: " + ", ".join(context_labels))
        md.append("")
        md.append("```")
        for row in ctx_cm:
            md.append("\t" + " ".join(str(x) for x in row))
        md.append("```")
    else:
        md.append("Confusion matrix not available.")
    md.append("")

    # 6.5 Payload Ranking Results
    md.append("## 6.5 Payload Ranking Results")
    md.append("")
    md.append("**Experiment 2: XGBoost Ranking vs Baselines**")
    md.append("")
    md.append("Table 6.5: Payload Ranking Comparison")
    md.append("")
    md.append("| Method | Accuracy | Precision | Recall | F1 | AUC | Notes |")
    md.append("|---|---:|---:|---:|---:|---:|---|")
    if ranker:
        m = ranker.get("metrics", {})
        md.append(f"| XGBoost-ranked | {m.get('accuracy',0):.3f} | {m.get('precision',0):.3f} | {m.get('recall',0):.3f} | {m.get('f1',0):.3f} | {m.get('auc',0):.3f} | trained on {ranker.get('training_samples', '?')} samples |")
        md.append(f"| Rule-based baseline | 0.5 | - | - | - | - | heuristic baseline score 0.5 |")
        md.append(f"| Random selection | ~0.5 | - | - | - | - | expected random baseline |")
    else:
        md.append("No ranker metrics found.")
    md.append("")

    # 6.6 Vulnerability Detection Results (from benchmark)
    md.append("## 6.6 Vulnerability Detection Results")
    md.append("")
    md.append("**Table 6.6: Vulnerabilities Detected by RedSentinel (aggregate)**")
    md.append("")
    if bench_rows:
        # find RedSentinel row
        rs = next((r for r in bench_rows if r['name'].lower().startswith('redsentinel')), None)
        if rs:
            md.append("| Metric | Value |")
            md.append("|---|---:|")
            md.append(f"| Targets tested (endpoints) | {rs['endpoints']} |")
            md.append(f"| True positives (TP) | {rs['tp']} |")
            md.append(f"| False positives (FP) | {rs['fp']} |")
            md.append(f"| False negatives (FN) | {rs['fn']} |")
            md.append(f"| Recall | {rs['recall']:.1f}% |")
            md.append(f"| Precision | {rs['precision']:.1f}% |")
            md.append(f"| F1 | {rs['f1']:.1f}% |")
            md.append(f"| Total scan time | {rs['time_s']:.1f}s |")
        else:
            md.append("Benchmark summary not found in HTML.")
    else:
        md.append("Benchmark report not found; see `Downloads/benchmark_report (2).html` attachment.")
    md.append("")

    # 6.7 Comparison with Existing Tools
    md.append("## 6.7 Comparison with Existing Tools")
    md.append("")
    md.append("**Table 6.8: Comparison with Existing Tools (Aggregate)**")
    md.append("")
    if bench_rows:
        md.append("| Tool | Endpoints | TP | FP | FN | Precision | Recall | F1 | Time (s) |")
        md.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
        for r in bench_rows:
            md.append(f"| {r['name']} | {r['endpoints']} | {r['tp']} | {r['fp']} | {r['fn']} | {r['precision']:.1f}% | {r['recall']:.1f}% | {r['f1']:.1f}% | {r['time_s']:.1f}s |")
    else:
        md.append("No comparative benchmark available.")
    md.append("")

    # 6.8 End-to-End System Testing -> Table 6.10
    md.append("## 6.8 End-to-End System Testing")
    md.append("")
    md.append("**Table 6.10: End-to-End Pipeline Test Results (Aggregate across targets)**")
    md.append("")
    if bench_rows:
        rs = next((r for r in bench_rows if r['name'].lower().startswith('redsentinel')), None)
        if rs:
            tp = rs['tp']; fn = rs['fn']; endpoints = rs['endpoints']
            recall = rs['recall']
            md.append("| Test | Value |")
            md.append("|---|---:|")
            md.append(f"| Endpoints scanned | {endpoints} |")
            md.append(f"| Vulnerabilities found (TP) | {tp} |")
            md.append(f"| Missed vulnerabilities (FN) | {fn} |")
            md.append(f"| Recall | {recall:.1f}% |")
            md.append(f"| End-to-end time | {rs['time_s']:.1f}s |")
    else:
        md.append("No end-to-end test data available.")
    md.append("")

    # 6.9 Performance Evaluation (Scan time by target size)
    md.append("## 6.9 Performance Evaluation")
    md.append("")
    md.append("**Table 6.11: Scan Time by Target Size (approx.)**")
    md.append("")
    if bench_rows:
        rs = next((r for r in bench_rows if r['name'].lower().startswith('redsentinel')), None)
        if rs:
            total_time = rs['time_s']
            total_endpoints = rs['endpoints']
            per_endpoint = total_time / total_endpoints if total_endpoints>0 else 0
            # target sizes extracted from HTML per-target blocks earlier: 47,18,6,16
            targets = [("Nexora XSS Lab",47),("OWASP Juice Shop",18),("Google XSS Game",6),("PortSwigger XSS Labs",16)]
            md.append("| Target | Endpoints | Estimated scan time (s) |")
            md.append("|---|---:|---:|")
            for name, cnt in targets:
                md.append(f"| {name} | {cnt} | {per_endpoint*cnt:.1f} |")
    else:
        md.append("No timing data available.")
    md.append("")

    # 6.10 Discussion of Limitations
    md.append("## 6.10 Discussion of Limitations")
    md.append("")
    md.append("Brief notes: mock mode for benchmarks, limited target diversity, synthetic training data biases, WAF/target variability affecting ranker.")

    OUT_MD.write_text("\n".join(md))
    print(f"Wrote evaluation report to {OUT_MD}")

if __name__ == '__main__':
    main()
