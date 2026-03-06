# ML Implementation Guide — RedSentinel v2.0

**Status:** Technical planning for v2.0 ML enhancements  
**Date:** March 6, 2026

This document provides concrete implementation details for building custom ML models using your existing infrastructure.

---

## Quick Start: Mutation XSS Classifier (First Model)

### Why Start Here?

1. **Lowest risk:** Replaces heuristic logic (easy rollback)
2. **Immediate data:** Mutation findings already labeled
3. **Reuses existing code:** DistilBERT pipeline exists
4. **Clear improvement:** Heuristic (70%) → ML (~85%+)
5. **Fast iteration:** 3-4 week implementation

### Architecture

```
                    ┌─────────────────────┐
                    │   Training Data     │
                    │  (mutation findings)│
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Feature Extraction │
                    │  [payload, response]│
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   DistilBERT Base   │
                    │  (frozen/shared)    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Classification Head │
                    │  (binary: mXSS?)    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │     Softmax Output  │
                    │  [probability, conf]│
                    └─────────────────────┘
```

### Implementation Steps

#### Step 1: Data Collection (Week 1)

Create data collector that hooks into fuzzer:

```python
# modules/fuzzer-module/mutation_xss_collector.py
import json
from pathlib import Path

class MutationXSSCollector:
    def __init__(self, data_dir='./mutation_training_data'):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
    
    def record_finding(self, payload: str, response_body: str, 
                       position: str, is_mutation: bool):
        """Record a mutation XSS finding for training"""
        record = {
            'payload': payload,
            'response_body': response_body[:2000],  # Truncate for size
            'position': position,
            'is_mutation_xss': is_mutation,
            'timestamp': datetime.now().isoformat(),
        }
        
        # Append to JSONL file
        output_file = self.data_dir / 'findings.jsonl'
        with open(output_file, 'a') as f:
            f.write(json.dumps(record) + '\n')

# Integration point in app.py:
collector = MutationXSSCollector()

if vuln_type == "mutation_xss":
    collector.record_finding(payload, response_body, position, True)
else:
    collector.record_finding(payload, response_body, position, False)
```

**Expected output after v1.0 deployments:**
- 500-2000 examples (payload, response, label)
- ~50-100MB JSONL file
- Ground truth from actual browser execution + manual review

#### Step 2: Data Preparation (Week 1-2)

```python
# ai/training/mutation_xss_dataset.py
import pandas as pd
from pathlib import Path
import random

class MutationXSSDatasetBuilder:
    def __init__(self, raw_data_path='mutation_training_data/findings.jsonl'):
        self.raw_data_path = Path(raw_data_path)
    
    def load_and_clean(self):
        """Load JSONL and clean duplicates"""
        df = pd.read_json(self.raw_data_path, lines=True)
        
        # Remove duplicates (same payload + response)
        df = df.drop_duplicates(subset=['payload', 'response_body'])
        
        # Remove malformed entries
        df = df[df['payload'].notna() & 
                df['response_body'].notna() &
                df['is_mutation_xss'].notna()]
        
        print(f"Loaded {len(df)} examples")
        return df
    
    def build_splits(self, df, train_frac=0.7, val_frac=0.15):
        """Create train/val/test splits"""
        # Stratified split by label
        mxss_true = df[df['is_mutation_xss'] == True]
        mxss_false = df[df['is_mutation_xss'] == False]
        
        # Sample stratified
        train_true = mxss_true.sample(frac=train_frac, random_state=42)
        remaining_true = mxss_true.drop(train_true.index)
        val_true = remaining_true.sample(frac=val_frac/(1-train_frac), random_state=42)
        test_true = remaining_true.drop(val_true.index)
        
        # Repeat for false class
        train_false = mxss_false.sample(frac=train_frac, random_state=42)
        remaining_false = mxss_false.drop(train_false.index)
        val_false = remaining_false.sample(frac=val_frac/(1-train_frac), random_state=42)
        test_false = remaining_false.drop(val_false.index)
        
        train = pd.concat([train_true, train_false])
        val = pd.concat([val_true, val_false])
        test = pd.concat([test_true, test_false])
        
        # Shuffle
        train = train.sample(frac=1, random_state=42)
        val = val.sample(frac=1, random_state=42)
        test = test.sample(frac=1, random_state=42)
        
        print(f"Train: {len(train)}, Val: {len(val)}, Test: {len(test)}")
        
        # Save as CSV
        train.to_csv('mutation_xss_train.csv', index=False)
        val.to_csv('mutation_xss_val.csv', index=False)
        test.to_csv('mutation_xss_test.csv', index=False)
        
        return train, val, test

# Run once to prepare data
builder = MutationXSSDatasetBuilder()
df = builder.load_and_clean()
train, val, test = builder.build_splits(df)
```

#### Step 3: Model Training (Week 2-3)

```python
# ai/training/train_mutation_xss.py
import torch
import pandas as pd
from transformers import DistilBertTokenizer, DistilBertModel
from sklearn.metrics import f1_score, precision_score, recall_score
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

class MutationXSSModel(nn.Module):
    def __init__(self, dropout=0.3):
        super().__init__()
        self.bert = DistilBertModel.from_pretrained('distilbert-base-uncased')
        
        # Freeze BERT weights
        for param in self.bert.parameters():
            param.requires_grad = False
        
        # Classification head (same as context classifier)
        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Linear(768, 1)  # Binary: mXSS or not
    
    def forward(self, input_ids, attention_mask):
        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        pooled = outputs[0][:, 0, :]  # [CLS] token
        dropped = self.dropout(pooled)
        logits = self.classifier(dropped)
        return logits

class MutationXSSTrainer:
    def __init__(self, model_name='mutation_xss_v1'):
        self.model_name = model_name
        self.tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
        self.model = MutationXSSModel()
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
    
    def prepare_data(self, csv_path, max_length=512):
        """Tokenize payloads + response snippets"""
        df = pd.read_csv(csv_path)
        
        # Combine payload + response for model input
        texts = []
        for row in df.itertuples():
            # First 256 chars of payload + first 256 of response
            combined = f"{row.payload[:256]} [SEP] {row.response_body[:256]}"
            texts.append(combined)
        
        # Tokenize
        encodings = self.tokenizer(
            texts,
            truncation=True,
            max_length=max_length,
            padding=True,
            return_tensors='pt'
        )
        
        # Labels
        labels = torch.tensor(df['is_mutation_xss'].astype(int).values)
        
        return TensorDataset(
            encodings['input_ids'],
            encodings['attention_mask'],
            labels
        )
    
    def train(self, train_csv, val_csv, epochs=5, batch_size=16, lr=2e-5):
        """Fine-tune the model"""
        train_dataset = self.prepare_data(train_csv)
        val_dataset = self.prepare_data(val_csv)
        
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size)
        
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=lr)
        loss_fn = nn.BCEWithLogitsLoss()
        
        for epoch in range(epochs):
            # Training
            self.model.train()
            total_loss = 0
            for batch in train_loader:
                input_ids, attention_mask, labels = batch
                input_ids = input_ids.to(self.device)
                attention_mask = attention_mask.to(self.device)
                labels = labels.unsqueeze(1).float().to(self.device)
                
                optimizer.zero_grad()
                logits = self.model(input_ids, attention_mask)
                loss = loss_fn(logits, labels)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            
            avg_train_loss = total_loss / len(train_loader)
            
            # Validation
            val_metrics = self.evaluate(val_loader)
            
            print(f"Epoch {epoch+1}: Train Loss={avg_train_loss:.4f}, "
                  f"Val F1={val_metrics['f1']:.4f}")
        
        # Save model
        torch.save(self.model.state_dict(), f'{self.model_name}.pth')
        print(f"Model saved to {self.model_name}.pth")
    
    def evaluate(self, val_loader):
        """Evaluate model on validation set"""
        self.model.eval()
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for batch in val_loader:
                input_ids, attention_mask, labels = batch
                input_ids = input_ids.to(self.device)
                attention_mask = attention_mask.to(self.device)
                
                logits = self.model(input_ids, attention_mask)
                preds = (torch.sigmoid(logits) > 0.5).int().cpu().numpy().flatten()
                
                all_preds.extend(preds)
                all_labels.extend(labels.numpy())
        
        return {
            'f1': f1_score(all_labels, all_preds),
            'precision': precision_score(all_labels, all_preds),
            'recall': recall_score(all_labels, all_preds),
        }

# Run training
if __name__ == '__main__':
    trainer = MutationXSSTrainer()
    trainer.train(
        train_csv='mutation_xss_train.csv',
        val_csv='mutation_xss_val.csv',
        epochs=5
    )
```

#### Step 4: Integration (Week 3-4)

Replace heuristic detection in fuzzer:

```python
# modules/fuzzer-module/app.py

# Load trained model once on startup
mutation_xss_model = MutationXSSModel()
mutation_xss_model.load_state_dict(torch.load('mutation_xss_v1.pth'))
mutation_xss_model.eval()
tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')

def detect_mutation_xss(payload: str, response_body: str, position: str) -> tuple[bool, float]:
    """
    Detect mutation XSS using trained model.
    Returns: (is_mutation_xss, confidence)
    """
    if not payload or not response_body:
        return False, 0.0
    
    # Prepare input
    combined = f"{payload[:256]} [SEP] {response_body[:256]}"
    encodings = tokenizer(
        combined,
        truncation=True,
        max_length=512,
        padding=True,
        return_tensors='pt',
    )
    
    # Inference
    with torch.no_grad():
        input_ids = encodings['input_ids'].to(device)
        attention_mask = encodings['attention_mask'].to(device)
        logits = mutation_xss_model(input_ids, attention_mask)
        prob = torch.sigmoid(logits).item()
    
    # Decision threshold
    is_mutation = prob > 0.5
    confidence = prob if is_mutation else 1 - prob
    
    return is_mutation, confidence

# Replace old heuristic
# OLD: vuln_type = detect_advanced_xss_type(payload, position, response_body, is_exact, is_executed)
# NEW:
if vuln_type == "reflected_xss" and position in ('html_body', 'attribute'):
    is_mutation, confidence = detect_mutation_xss(payload, response_body, position)
    if is_mutation and confidence > 0.7:
        vuln_type = "mutation_xss"
        logger.info(f"Detected mutation XSS (confidence={confidence:.2f})")
```

#### Step 5: Evaluation (Week 4)

```python
# ai/training/evaluate_mutation_model.py
import torch
from mutations_xss_dataset import MutationXSSModel

def evaluate_on_test_set(model_path, test_csv):
    """Evaluate trained model on test set"""
    model = MutationXSSModel()
    model.load_state_dict(torch.load(model_path))
    model.eval()
    
    test_dataset = prepare_data(test_csv)
    test_loader = DataLoader(test_dataset, batch_size=16)
    
    metrics = evaluate(model, test_loader)
    
    print("=" * 40)
    print("MUTATION XSS CLASSIFIER - TEST SET")
    print("=" * 40)
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"F1 Score:  {metrics['f1']:.4f}")
    print("=" * 40)
    
    # Confusion matrix
    print("\nConfusion Matrix:")
    print(f"TP: {metrics['tp']}, FP: {metrics['fp']}")
    print(f"FN: {metrics['fn']}, TN: {metrics['tn']}")
    
    return metrics['f1'] > 0.85  # Pass threshold

if __name__ == '__main__':
    success = evaluate_on_test_set('mutation_xss_v1.pth', 'mutation_xss_test.csv')
    if success:
        print("\n✅ Model passes evaluation threshold (F1 > 0.85)")
        print("Ready for production deployment!")
    else:
        print("\n❌ Model doesn't meet quality threshold")
        print("Consider more training data or hyperparameter tuning")
```

---

## False Positive Filter (Second Model)

### Quick Implementation

Would follow same pattern as Mutation XSS classifier but:

**Input:** `[payload, reflection_position, response_context, tag_around_reflection]`  
**Output:** `is_real_xss` (probability)  
**Data:** Historical findings + manual review labels  

**Timeline:** 4-5 weeks (after mXSS classifier)

---

## Monitoring & Iteration

### Production Monitoring

```python
# modules/fuzzer-module/model_metrics.py
class ModelMetricsCollector:
    """Track model performance in production"""
    
    def record_prediction(self, payload, position, model_confidence, actual_executed):
        """Record prediction for later analysis"""
        self.metrics.append({
            'timestamp': datetime.now(),
            'payload': payload,
            'position': position,
            'model_confidence': model_confidence,
            'actual_executed': actual_executed,
            'correct': (model_confidence > 0.5) == actual_executed,
        })
    
    def get_accuracy(self, window_hours=24):
        """Rolling accuracy window"""
        cutoff = datetime.now() - timedelta(hours=window_hours)
        recent = [m for m in self.metrics if m['timestamp'] > cutoff]
        
        if not recent:
            return None
        
        correct = sum(1 for m in recent if m['correct'])
        return correct / len(recent)
    
    def alert_on_drift(self, threshold=0.15):
        """Alert if accuracy drops below threshold"""
        accuracy = self.get_accuracy(window_hours=24)
        
        if accuracy and accuracy < threshold:
            logger.warning(
                f"Model accuracy drifted: {accuracy:.2%} "
                f"(threshold: {threshold:.2%})"
            )
            return True
        return False
```

### Retraining Pipeline

Monthly retraining to incorporate new findings:

```bash
#!/bin/bash
# scripts/monthly_retraining.sh

# Collect new findings
python3 ai/training/mutation_xss_collector.py collect

# Rebuild dataset
python3 ai/training/mutation_xss_dataset.py prepare \
    --output mutation_xss_train.csv

# Retrain model
python3 ai/training/train_mutation_xss.py \
    --epochs 5 \
    --output mutation_xss_latest.pth

# Evaluate
python3 ai/training/evaluate_mutation_model.py \
    --model mutation_xss_latest.pth

# If passes evaluation:
# cp mutation_xss_latest.pth mutation_xss_prod.pth
# restart fuzzer service
```

---

## Checklist

### To Start Mutation XSS Classifier:

- [ ] Deploy v1.0 to production
- [ ] Run for 2-3 weeks to collect mutation findings (~500 examples)
- [ ] Manual review of findings (confirm labels)
- [ ] Prepare dataset with stratified splits
- [ ] Train DistilBERT classifier (5 epochs)
- [ ] Evaluate on test set (target F1 > 0.85)
- [ ] Integration testing with fuzzer
- [ ] A/B test vs heuristic approach (canary deployment)
- [ ] Monitor accuracy in production (24/7)
- [ ] Full rollout when stable

### Infrastructure Needed:

- [ ] GPU (optional but faster): 4+ GB VRAM
- [ ] Storage: 50-100GB for training data
- [ ] CI/CD: Automated retraining pipeline
- [ ] Monitoring: Model accuracy tracking
- [ ] Versioning: Model checkpoints + metadata

---

## Success Metrics

| Metric | Heuristic | Target |
|--------|-----------|--------|
| Precision | 70% | 92%+ |
| Recall | 65% | 85%+ |
| F1 Score | 0.67 | 0.88+ |
| False Positive Rate | 30% | <8% |
| Inference Time | <50ms | <100ms |

---

**Next Steps:**
1. Deploy v1.0 to production  
2. Start collecting mutation findings  
3. Begin labeling after 2-3 weeks  
4. Kick off training cycle in month 2  

