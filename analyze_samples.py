import json

with open('dataset/ranker_training/ranker_training_samples.jsonl') as f:
    samples = [json.loads(l) for l in f]

success = [s for s in samples if s.get('success')]
executed = [s for s in samples if s.get('executed')]

contexts = {}
techniques = {}

for s in samples:
    ctx = s.get('context', '?')
    contexts[ctx] = contexts.get(ctx, 0) + 1
    tec = s.get('technique', '?')
    techniques[tec] = techniques.get(tec, 0) + 1

print('Total ranker samples:', len(samples))
print('Success:', len(success))
print('Executed:', len(executed))
print('\nContexts:')
for k, v in sorted(contexts.items(), key=lambda x: -x[1]):
    print(f'  {k}: {v}')
print('\nTechniques:')
for k, v in sorted(techniques.items(), key=lambda x: -x[1]):
    print(f'  {k}: {v}')
