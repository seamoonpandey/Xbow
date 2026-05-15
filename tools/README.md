# RedSentinel Tools

Operational and ML utility scripts that are useful outside the running
services.

## Layout

```text
inference/             Context/severity inference CLI and export tools
inference/export/      TorchScript and ONNX exporters
requirements.txt       Shared tool dependencies
```

`tools/inference/` is the canonical home for model inference and export
helpers. Generated tool outputs go under `outputs/`, which is ignored by Git.
