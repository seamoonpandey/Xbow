#!/usr/bin/env python3
"""
prepare_enriched_training_data.py — Converts enriched JSONL training data to CSV for model retraining.

This script:
1. Reads ranker_training_samples.jsonl (collected from fuzzer)
2. Filters for successful samples
3. Creates context-aware CSV with enhanced fields
4. Outputs to train/val/test splits

Usage:
    python prepare_enriched_training_data.py --input /path/to/ranker_training_samples.jsonl --output /path/to/enriched_training.csv
"""

import argparse
import json
import csv
import sys
import os
from pathlib import Path
from typing import Generator
import random

random.seed(42)


def read_training_samples(jsonl_path: Path) -> Generator[dict, None, None]:
    """Read training samples from JSONL file."""
    if not jsonl_path.exists():
        print(f"Error: {jsonl_path} does not exist")
        sys.exit(1)
    
    with open(jsonl_path, 'r') as f:
        for line in f:
            try:
                sample = json.loads(line)
                yield sample
            except json.JSONDecodeError as e:
                print(f"Warning: Failed to parse JSON: {e}")
                continue


def encode_context_enrichment(sample: dict) -> str:
    """
    Create a text representation of context enrichment fields.
    This will be concatenated with the payload for model input.
    """
    context_parts = []
    
    if sample.get("sink_name"):
        context_parts.append(f"sink:{sample['sink_name']}")
    if sample.get("source_name"):
        context_parts.append(f"source:{sample['source_name']}")
    if sample.get("reflection_position"):
        context_parts.append(f"position:{sample['reflection_position']}")
    if sample.get("response_snippet"):
        # Truncate snippet to avoid huge entries
        snippet = sample['response_snippet'][:100]
        context_parts.append(f"snippet_context:{snippet}")
    
    return " ".join(context_parts)


# Raw context label values from fuzzer → normalized label mapping.
# Fuzzer records raw reflection positions (e.g. "html_body") which must
# be mapped to the classifier's canonical CONTEXT_LABELS to avoid data loss.
RAW_CONTEXT_NORMALIZATION = {
    "html_body": "tag_injection",
    "attribute": "attribute_escape",
    "js_block": "script_injection",
    "js_string": "js_uri",
    "url": "js_uri",
}


def _lower_text(value) -> str:
    """Return a lowercase string for optional JSON fields."""
    if value is None:
        return ""
    return str(value).lower()


def infer_context_label(sample: dict) -> str:
    """
    Infer the context label from available fields.
    Falls back to 'generic' if uncertain.
    """
    # If explicitly provided, normalize it
    if sample.get("context") and sample["context"] != "generic":
        raw = sample["context"]
        # Normalize raw fuzzer context labels to canonical training labels
        return RAW_CONTEXT_NORMALIZATION.get(raw, raw)
    
    # Try to infer from source/sink
    source = _lower_text(sample.get("source_name"))
    sink = _lower_text(sample.get("sink_name"))
    position = _lower_text(sample.get("reflection_position"))
    
    sink_to_context = {
        "innerhtml": "dom_sink",
        "document.write": "script_injection",
        "setinterval": "script_injection",
        "settimeout": "script_injection",
        "eval": "script_injection",
        "function_constructor": "script_injection",
        "onload": "event_handler",
        "onerror": "event_handler",
        "onclick": "event_handler",
        "href": "js_uri",
        "src": "js_uri",
    }
    
    for pattern, ctx in sink_to_context.items():
        if pattern in sink:
            return ctx
    
    position_to_context = {
        "attribute": "attribute_escape",
        "script": "script_injection",
        "html_body": "tag_injection",
        "style": "tag_injection",
    }
    
    if position in position_to_context:
        return position_to_context[position]
    
    return "generic"


def infer_severity_from_execution(sample: dict) -> str:
    """
    Infer severity from execution data if not explicitly provided.
    """
    provided_severity = _lower_text(sample.get("severity"))
    if provided_severity in ["low", "medium", "high"]:
        return provided_severity
    
    # Execution -> high confidence
    if sample.get("executed") or sample.get("dialog_triggered"):
        return "high"
    
    # Exact reflection in dangerous position -> medium
    if sample.get("exact_match") and sample.get("reflection_position") in {"html_body", "attribute", "script"}:
        return "medium"
    
    # Decoded-only reflection -> low
    if sample.get("reflected") and not sample.get("exact_match"):
        return "low"
    
    return "medium"


def prepare_training_data(
    jsonl_path: Path,
    output_path: Path,
    min_samples: int = 10,
) -> None:
    """
    Convert JSONL training data to enriched CSV format.
    """
    samples = []
    
    print(f"Reading training samples from {jsonl_path}...")
    for sample in read_training_samples(jsonl_path):
        # Only use successful samples (high signal-to-noise ratio)
        if not sample.get("success", False):
            continue
        
        # Enhance context inference
        context = infer_context_label(sample)
        severity = infer_severity_from_execution(sample)
        
        # Create enriched payload representation
        context_enrichment = encode_context_enrichment(sample)
        payload_with_context = sample.get("payload_text", "")
        if context_enrichment:
            payload_with_context = f"{payload_with_context} [{context_enrichment}]"
        
        enriched_sample = {
            "payload": sample.get("payload_text", ""),
            "payload_with_context": payload_with_context,
            "context": context,
            "severity": severity,
            "executed": sample.get("executed", False),
            "reflected": sample.get("reflected", False),
            "exact_match": sample.get("exact_match", False),
            "reflection_position": sample.get("reflection_position", ""),
            "source": sample.get("source_name", ""),
            "sink": sample.get("sink_name", ""),
            "technique": sample.get("technique", "original"),
            "url": sample.get("url", ""),
        }
        samples.append(enriched_sample)
    
    if len(samples) < min_samples:
        print(f"Warning: Only {len(samples)} successful samples found (minimum {min_samples})")
    
    print(f"Loaded {len(samples)} samples")
    
    # Shuffle and split
    random.shuffle(samples)
    train_split = int(0.7 * len(samples))
    val_split = int(0.85 * len(samples))
    
    train_samples = samples[:train_split]
    val_samples = samples[train_split:val_split]
    test_samples = samples[val_split:]
    
    # Write training data in two variants
    fieldnames = ["payload", "context", "severity"]
    
    # Variant 1: Original format (for backward compatibility)
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for sample in samples:
            writer.writerow({
                "payload": sample["payload"],
                "context": sample["context"],
                "severity": sample["severity"],
            })
    
    print(f"Wrote all samples to {output_path}")
    
    # Variant 2: Enhanced format (with context enrichment)
    enriched_fieldnames = [
        "payload", "payload_with_context", "context", "severity",
        "source", "sink", "reflection_position", "technique"
    ]
    
    output_enriched = output_path.parent / f"{output_path.stem}_enriched.csv"
    with open(output_enriched, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=enriched_fieldnames)
        writer.writeheader()
        for sample in samples:
            writer.writerow({k: sample.get(k, "") for k in enriched_fieldnames})
    
    print(f"Wrote enriched samples to {output_enriched}")
    
    # Write splits
    splits_dir = output_path.parent / "splits_from_ranker"
    splits_dir.mkdir(exist_ok=True)
    
    for split_name, split_samples in [
        ("train", train_samples),
        ("val", val_samples),
        ("test", test_samples),
    ]:
        split_path = splits_dir / f"{split_name}.csv"
        with open(split_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for sample in split_samples:
                writer.writerow({k: sample.get(k, "") for k in fieldnames})
        print(f"Wrote {len(split_samples)} {split_name} samples to {split_path}")


if __name__ == "__main__":
    # Compute project root and dataset paths relative to this script
    script_dir = Path(__file__).resolve().parent  # ai/training/
    project_root = script_dir.parent.parent      # project root
    dataset_dir = project_root / "dataset"
    ranker_training_dir = dataset_dir / "ranker_training"
    processed_dir = dataset_dir / "processed"
    
    # Default paths with fallback to Docker paths if env var set
    default_input = Path(os.environ.get(
        "TRAINING_DATA_FILE",
        str(ranker_training_dir / "ranker_training_samples.jsonl")
    ))
    default_output = Path(os.environ.get(
        "ENRICHED_TRAINING_CSV",
        str(processed_dir / "enriched_training.csv")
    ))
    
    parser = argparse.ArgumentParser(
        description="Prepare enriched training data for model retraining"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=default_input,
        help="Path to ranker_training_samples.jsonl",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=default_output,
        help="Output path for enriched training CSV",
    )
    
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    
    prepare_training_data(args.input, args.output)
    print("✓ Training data preparation complete")
