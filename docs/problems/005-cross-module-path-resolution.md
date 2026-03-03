# PROBLEM-005: Cross-Module Python Path Resolution

## Summary

Training scripts in `ai/training/` could not import the `feature_extractor` module from `modules/payload-gen-module/` because Python's import system doesn't resolve cross-directory imports without explicit path manipulation. Using `Path(__file__)` without `.resolve()` produced incorrect paths in some environments.

## Discovery

**Date:** March 3, 2026
**How:** Running `python ai/training/train_ranker.py` from the project root failed with:

```
ModuleNotFoundError: No module named 'feature_extractor'
```

Even after adding `sys.path.insert()`, using `Path(__file__).parent.parent.parent` sometimes resolved to a symlinked or relative path that didn't match the actual filesystem location.

## What Existed Before

Initial attempt used relative `Path(__file__)` without `.resolve()`:

```python
# ai/training/train_ranker.py
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "modules" / "payload-gen-module"))
```

In some environments (Docker, symlinked workspaces, devcontainers), `__file__` can be a relative path like `ai/training/train_ranker.py` rather than an absolute path. When you do `.parent.parent.parent` on a relative path, you get `../..` which may not resolve to the project root.

## Root Cause

**`Path(__file__)` is not guaranteed to be absolute.** Python sets `__file__` to whatever path was used to invoke the script. If you run `python ai/training/train_ranker.py` from the project root, `__file__` is `ai/training/train_ranker.py` (relative). But `.parent.parent.parent` on that gives `.` (current directory), not the actual project root.

This works accidentally when your CWD is the project root, but breaks when:
- Running from a different directory (`cd ai && python training/train_ranker.py`)
- Running inside Docker where the working directory differs
- Your IDE runs scripts with a different CWD

## Solution

Always use `.resolve()` to get the canonical absolute path:

```python
# Correct: always resolves to absolute path
sys.path.insert(0, str(
    Path(__file__).resolve().parent.parent.parent / "modules" / "payload-gen-module"
))

TRAINING_DATA_FILE = Path(__file__).resolve().parent.parent.parent / "dataset" / "ranker_training" / "ranker_training_samples.jsonl"
MODEL_OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "model" / "ranker"
```

Applied consistently across all files:
- `ai/training/train_ranker.py`
- `ai/training/generate_ranker_data.py`
- `ai/training/config.py`
- `modules/payload-gen-module/xgboost_ranker.py` (uses env var override for Docker)

## Verification

```bash
# These all work now:
cd /workspaces/ratopaleydai && python ai/training/train_ranker.py      # from root
cd /workspaces/ratopaleydai/ai && python training/train_ranker.py      # from subdirectory
python /workspaces/ratopaleydai/ai/training/train_ranker.py            # absolute path
```

## Pattern / Lesson

> **Always use `Path(__file__).resolve()` before navigating with `.parent` in Python scripts that reference other parts of the project.**
>
> `__file__` is unreliable across environments. `.resolve()` canonicalizes it to an absolute, symlink-resolved path that works regardless of CWD.
>
> For Docker deployments, add an environment variable override so paths can be remapped:
> ```python
> MODEL_DIR = Path(os.environ.get("RANKER_MODEL_DIR",
>     str(Path(__file__).resolve().parent.parent.parent / "model" / "ranker")))
> ```
>
> **Rule of thumb:** If a path depends on `__file__`, it must use `.resolve()`. No exceptions.
