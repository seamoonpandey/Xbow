"""
ai classifier — distilbert inference for xss context classification
loads the trained model checkpoint and tokenizer for real-time classification.
falls back to rule-based classification when model is unavailable.
"""

import logging
import os
from pathlib import Path

import torch
from transformers import DistilBertTokenizerFast

logger = logging.getLogger(__name__)

# label mappings (must match training config)
CONTEXT_LABELS = [
    "script_injection",
    "event_handler",
    "js_uri",
    "tag_injection",
    "template_injection",
    "dom_sink",
    "attribute_escape",
    "generic",
]

SEVERITY_LABELS = ["low", "medium", "high"]

# map ai labels to reflection context types
AI_TO_CONTEXT = {
    "script_injection": "js_block",
    "event_handler": "attribute",
    "js_uri": "url",
    "tag_injection": "html_body",
    "template_injection": "js_block",
    "dom_sink": "js_block",
    "attribute_escape": "attribute",
    "generic": "html_body",
}

MODEL_DIR = Path(os.getenv("MODEL_DIR", "/app/model"))
CHECKPOINT_PATH = MODEL_DIR / "checkpoints" / "best.pt"
MAX_LENGTH = 128


class AIClassifier:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self._load_model()

    def _load_model(self):
        """load the trained distilbert model and tokenizer"""
        try:
            if not CHECKPOINT_PATH.exists():
                logger.warning(f"checkpoint not found at {CHECKPOINT_PATH}, using fallback")
                return

            # import the model class
            import sys
            model_parent = str(MODEL_DIR.parent)
            if model_parent not in sys.path:
                sys.path.insert(0, model_parent)
            from model.xss_classifier import XSSClassifier

            self.model = XSSClassifier(
                num_contexts=len(CONTEXT_LABELS),
                num_severities=len(SEVERITY_LABELS),
            )

            checkpoint = torch.load(CHECKPOINT_PATH, map_location=self.device, weights_only=False)
            if "model_state_dict" in checkpoint:
                self.model.load_state_dict(checkpoint["model_state_dict"])
            else:
                self.model.load_state_dict(checkpoint)

            self.model.to(self.device)
            self.model.eval()

            self.tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")

            logger.info(f"ai classifier loaded from {CHECKPOINT_PATH} on {self.device}")

        except Exception as e:
            logger.error(f"failed to load model: {e}")
            self.model = None
            self.tokenizer = None

    @property
    def available(self) -> bool:
        return self.model is not None and self.tokenizer is not None

    def classify(self, text: str) -> dict:
        """
        classify a text snippet (e.g. reflected context).
        returns {context_label, context_type, confidence, severity, severity_confidence}
        """
        if not self.available:
            return self._fallback_classify(text)

        try:
            encoding = self.tokenizer(
                text,
                max_length=MAX_LENGTH,
                padding="max_length",
                truncation=True,
                return_tensors="pt",
            )

            input_ids = encoding["input_ids"].to(self.device)
            attention_mask = encoding["attention_mask"].to(self.device)

            with torch.no_grad():
                ctx_logits, sev_logits = self.model(input_ids, attention_mask)

            ctx_probs = torch.softmax(ctx_logits, dim=1)
            sev_probs = torch.softmax(sev_logits, dim=1)

            ctx_idx = ctx_probs.argmax(dim=1).item()
            sev_idx = sev_probs.argmax(dim=1).item()

            ctx_label = CONTEXT_LABELS[ctx_idx]
            ctx_confidence = ctx_probs[0, ctx_idx].item()
            sev_label = SEVERITY_LABELS[sev_idx]
            sev_confidence = sev_probs[0, sev_idx].item()

            return {
                "context_label": ctx_label,
                "context_type": AI_TO_CONTEXT.get(ctx_label, "html_body"),
                "confidence": round(ctx_confidence, 4),
                "severity": sev_label,
                "severity_confidence": round(sev_confidence, 4),
            }

        except Exception as e:
            logger.error(f"inference error: {e}")
            return self._fallback_classify(text)

    def classify_batch(self, texts: list[str]) -> list[dict]:
        """classify multiple texts in a single batch"""
        if not self.available:
            return [self._fallback_classify(t) for t in texts]

        try:
            encoding = self.tokenizer(
                texts,
                max_length=MAX_LENGTH,
                padding="max_length",
                truncation=True,
                return_tensors="pt",
            )

            input_ids = encoding["input_ids"].to(self.device)
            attention_mask = encoding["attention_mask"].to(self.device)

            with torch.no_grad():
                ctx_logits, sev_logits = self.model(input_ids, attention_mask)

            ctx_probs = torch.softmax(ctx_logits, dim=1)
            sev_probs = torch.softmax(sev_logits, dim=1)

            results = []
            for i in range(len(texts)):
                ctx_idx = ctx_probs[i].argmax().item()
                sev_idx = sev_probs[i].argmax().item()
                ctx_label = CONTEXT_LABELS[ctx_idx]

                results.append({
                    "context_label": ctx_label,
                    "context_type": AI_TO_CONTEXT.get(ctx_label, "html_body"),
                    "confidence": round(ctx_probs[i, ctx_idx].item(), 4),
                    "severity": SEVERITY_LABELS[sev_idx],
                    "severity_confidence": round(sev_probs[i, sev_idx].item(), 4),
                })
            return results

        except Exception as e:
            logger.error(f"batch inference error: {e}")
            return [self._fallback_classify(t) for t in texts]

    @staticmethod
    def _fallback_classify(text: str) -> dict:
        """rule-based fallback when model is unavailable"""
        text_lower = text.lower()

        if "<script" in text_lower or "javascript:" in text_lower:
            return {
                "context_label": "script_injection",
                "context_type": "js_block",
                "confidence": 0.6,
                "severity": "high",
                "severity_confidence": 0.5,
            }
        if "onerror" in text_lower or "onload" in text_lower or "onclick" in text_lower:
            return {
                "context_label": "event_handler",
                "context_type": "attribute",
                "confidence": 0.6,
                "severity": "high",
                "severity_confidence": 0.5,
            }
        if "href=" in text_lower or "src=" in text_lower:
            return {
                "context_label": "js_uri",
                "context_type": "url",
                "confidence": 0.5,
                "severity": "medium",
                "severity_confidence": 0.5,
            }
        if "<" in text and ">" in text:
            return {
                "context_label": "tag_injection",
                "context_type": "html_body",
                "confidence": 0.5,
                "severity": "medium",
                "severity_confidence": 0.5,
            }

        return {
            "context_label": "generic",
            "context_type": "html_body",
            "confidence": 0.3,
            "severity": "low",
            "severity_confidence": 0.5,
        }
