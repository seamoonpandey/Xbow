"""
integration tests — cross-module data flow
verifies that the output schema from one module is compatible
as input to the next module in the pipeline:
  context → payload-gen → fuzzer

uses mocked heavy dependencies but exercises pydantic validation
and response schema compliance end-to-end.
"""

import sys
import os
import importlib.util
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

# ── load each module's app under unique names ────────────────

_modules_dir = os.path.join(os.path.dirname(__file__), "..", "modules")


def _load_app(module_dir, module_name):
    """load a module's app.py under a unique name to avoid collisions."""
    full_dir = os.path.join(_modules_dir, module_dir)
    if full_dir not in sys.path:
        sys.path.insert(0, full_dir)
    parent_dir = os.path.dirname(full_dir)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    spec = importlib.util.spec_from_file_location(
        module_name, os.path.join(full_dir, "app.py")
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


context_mod = _load_app("context-module", "integration_context_app")
payloadgen_mod = _load_app("payload-gen-module", "integration_payloadgen_app")
fuzzer_mod = _load_app("fuzzer-module", "integration_fuzzer_app")


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ── test: context module output schema ───────────────────────

@pytest.mark.anyio
@patch("integration_context_app.inject_probes", new_callable=AsyncMock)
@patch("integration_context_app.fuzz_chars", new_callable=AsyncMock)
@patch("integration_context_app.analyze_reflection")
@patch("integration_context_app.get_primary_context")
@patch("integration_context_app.get_dom_context")
@patch("integration_context_app.classifier")
async def test_context_output_schema(
    mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """verify context module returns valid schema for payload-gen input"""
    mock_probes.return_value = {
        "q": {"marker": "rsp123", "body": "<html>rsp123</html>", "status_code": 200},
        "name": {"marker": "rsp456", "body": "<html>safe</html>", "status_code": 200},
    }
    mock_reflection.side_effect = lambda body, marker: (
        [{"position": "html_text", "context_snippet": f"<p>{marker}</p>"}]
        if marker in body
        else []
    )
    mock_primary.return_value = "html_text"
    mock_dom.return_value = "html_text"
    mock_classifier.classify.return_value = {"context_type": "html_text", "confidence": 0.95}
    mock_fuzz.return_value = ["<", ">", "'", '"']

    async with AsyncClient(
        transport=ASGITransport(app=context_mod.app), base_url="http://test"
    ) as client:
        resp = await client.post("/analyze", json={
            "url": "https://target.com/search",
            "params": ["q", "name"],
            "waf": "none",
        })

    assert resp.status_code == 200
    context_map = resp.json()

    # validate the schema shape matches what payload-gen expects
    assert isinstance(context_map, dict)
    for param, ctx in context_map.items():
        assert "reflects_in" in ctx
        assert "allowed_chars" in ctx
        assert "context_confidence" in ctx
        assert isinstance(ctx["reflects_in"], str)
        assert isinstance(ctx["allowed_chars"], list)
        assert isinstance(ctx["context_confidence"], (int, float))

    # q should be reflected, name should not
    assert context_map["q"]["reflects_in"] == "html_text"
    assert context_map["name"]["reflects_in"] == "none"

    return context_map


# ── test: payload-gen accepts context output ─────────────────

@pytest.mark.anyio
@patch("integration_payloadgen_app.select_payloads")
@patch("integration_payloadgen_app.mutate_payloads")
@patch("integration_payloadgen_app.rank_payloads")
async def test_payloadgen_accepts_context_output(mock_rank, mock_mutate, mock_select):
    """verify payload-gen accepts the context module output schema"""
    # simulate context module output
    context_map = {
        "q": {"reflects_in": "html_text", "allowed_chars": ["<", ">", "'"], "context_confidence": 0.92},
        "name": {"reflects_in": "none", "allowed_chars": [], "context_confidence": 0.0},
    }

    payloadgen_mod.bank = MagicMock()
    payloadgen_mod.bank.size = 100

    mock_select.return_value = [
        {"payload": "<script>alert(1)</script>", "technique": "basic"},
    ]
    mock_mutate.return_value = [
        {"payload": "<script>alert(1)</script>", "technique": "basic"},
        {"payload": "<ScRiPt>alert(1)</ScRiPt>", "technique": "case_swap"},
    ]
    mock_rank.return_value = [
        {"payload": "<ScRiPt>alert(1)</ScRiPt>", "technique": "case_swap", "score": 0.9},
        {"payload": "<script>alert(1)</script>", "technique": "basic", "score": 0.8},
    ]

    async with AsyncClient(
        transport=ASGITransport(app=payloadgen_mod.app), base_url="http://test"
    ) as client:
        resp = await client.post("/generate", json={
            "contexts": context_map,
            "waf": "none",
            "max_payloads": 10,
        })

    assert resp.status_code == 200
    data = resp.json()

    # validate schema for fuzzer input
    assert "payloads" in data
    assert isinstance(data["payloads"], list)
    for p in data["payloads"]:
        assert "payload" in p
        assert "target_param" in p
        assert "context" in p
        assert "confidence" in p
        assert isinstance(p["payload"], str)
        assert isinstance(p["target_param"], str)

    return data["payloads"]


# ── test: fuzzer accepts payload-gen output ──────────────────

class MockSendResult:
    def __init__(self, payload, target_param, response_body, status_code):
        self.payload = payload
        self.target_param = target_param
        self.response_body = response_body
        self.status_code = status_code
        self.method = "GET"
        self.error = None


class MockSendBatch:
    def __init__(self, results):
        self.results = results


class MockScanResult:
    def __init__(self, findings=None):
        self.findings = findings or []


@pytest.mark.anyio
@patch("integration_fuzzer_app.send_payloads", new_callable=AsyncMock)
@patch("integration_fuzzer_app.check_reflection_batch")
@patch("integration_fuzzer_app.verify_payloads", new_callable=AsyncMock)
@patch("integration_fuzzer_app.scan_response_body")
async def test_fuzzer_accepts_payloadgen_output(
    mock_dom_scan, mock_verify, mock_reflect, mock_send
):
    """verify fuzzer accepts the payload-gen output schema"""
    # simulate payload-gen output
    payloads = [
        {"payload": "<ScRiPt>alert(1)</ScRiPt>", "target_param": "q", "confidence": 0.9},
        {"payload": "<script>alert(1)</script>", "target_param": "q", "confidence": 0.8},
    ]

    mock_send.return_value = MockSendBatch([
        MockSendResult(
            payload=p["payload"],
            target_param=p["target_param"],
            response_body=f"<html>{p['payload']}</html>",
            status_code=200,
        )
        for p in payloads
    ])
    mock_reflect.return_value = [
        {
            "payload": p["payload"],
            "target_param": p["target_param"],
            "reflected": True,
            "status_code": 200,
            "reflection_position": "body",
            "context_snippet": f"<html>{p['payload']}</html>",
        }
        for p in payloads
    ]
    mock_verify.return_value = []
    mock_dom_scan.return_value = MockScanResult([])

    async with AsyncClient(
        transport=ASGITransport(app=fuzzer_mod.app), base_url="http://test"
    ) as client:
        resp = await client.post("/test", json={
            "url": "https://target.com/search",
            "payloads": payloads,
            "verify_execution": False,
            "timeout": 5000,
        })

    assert resp.status_code == 200
    data = resp.json()

    # validate schema for core's consumption
    assert "results" in data
    assert isinstance(data["results"], list)
    for r in data["results"]:
        assert "payload" in r
        assert "target_param" in r
        assert "reflected" in r
        assert "executed" in r
        assert "vuln" in r
        assert isinstance(r["reflected"], bool)
        assert isinstance(r["vuln"], bool)


# ── test: full pipeline schema compatibility ─────────────────

@pytest.mark.anyio
@patch("integration_context_app.inject_probes", new_callable=AsyncMock)
@patch("integration_context_app.fuzz_chars", new_callable=AsyncMock)
@patch("integration_context_app.analyze_reflection")
@patch("integration_context_app.get_primary_context")
@patch("integration_context_app.get_dom_context")
@patch("integration_context_app.classifier")
@patch("integration_payloadgen_app.select_payloads")
@patch("integration_payloadgen_app.mutate_payloads")
@patch("integration_payloadgen_app.rank_payloads")
@patch("integration_fuzzer_app.send_payloads", new_callable=AsyncMock)
@patch("integration_fuzzer_app.check_reflection_batch")
@patch("integration_fuzzer_app.verify_payloads", new_callable=AsyncMock)
@patch("integration_fuzzer_app.scan_response_body")
async def test_full_pipeline_data_flow(
    mock_dom_scan, mock_verify, mock_reflect, mock_send,
    mock_rank, mock_mutate, mock_select,
    mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes,
):
    """end-to-end data flow: context output → payload-gen → fuzzer"""
    # ── context module setup ──
    mock_probes.return_value = {
        "q": {"marker": "rsp123", "body": "<html>rsp123</html>", "status_code": 200},
    }
    mock_reflection.return_value = [
        {"position": "html_text", "context_snippet": "<p>rsp123</p>"}
    ]
    mock_primary.return_value = "html_text"
    mock_dom.return_value = "html_text"
    mock_classifier.classify.return_value = {"context_type": "html_text", "confidence": 0.95}
    mock_fuzz.return_value = ["<", ">", "'", '"']

    # step 1: call context module
    async with AsyncClient(
        transport=ASGITransport(app=context_mod.app), base_url="http://test"
    ) as client:
        ctx_resp = await client.post("/analyze", json={
            "url": "https://target.com", "params": ["q"], "waf": "none",
        })
    assert ctx_resp.status_code == 200
    context_map = ctx_resp.json()

    # ── payload-gen setup ──
    payloadgen_mod.bank = MagicMock()
    payloadgen_mod.bank.size = 100
    mock_select.return_value = [{"payload": "<svg onload=alert(1)>", "technique": "basic"}]
    mock_mutate.return_value = [{"payload": "<svg onload=alert(1)>", "technique": "basic"}]
    mock_rank.return_value = [{"payload": "<svg onload=alert(1)>", "technique": "basic", "score": 0.92}]

    # step 2: feed context output into payload-gen
    async with AsyncClient(
        transport=ASGITransport(app=payloadgen_mod.app), base_url="http://test"
    ) as client:
        gen_resp = await client.post("/generate", json={
            "contexts": context_map,
            "waf": "none",
            "max_payloads": 10,
        })
    assert gen_resp.status_code == 200
    gen_payloads = gen_resp.json()["payloads"]
    assert len(gen_payloads) >= 1

    # ── fuzzer setup ──
    mock_send.return_value = MockSendBatch([
        MockSendResult(
            payload=gen_payloads[0]["payload"],
            target_param=gen_payloads[0]["target_param"],
            response_body=f"<html>{gen_payloads[0]['payload']}</html>",
            status_code=200,
        ),
    ])
    mock_reflect.return_value = [
        {
            "payload": gen_payloads[0]["payload"],
            "target_param": gen_payloads[0]["target_param"],
            "reflected": True,
            "status_code": 200,
            "reflection_position": "body",
            "context_snippet": f"<html>{gen_payloads[0]['payload']}</html>",
        },
    ]
    mock_verify.return_value = []
    mock_dom_scan.return_value = MockScanResult([])

    # step 3: feed payload-gen output into fuzzer
    fuzzer_payloads = [
        {"payload": p["payload"], "target_param": p["target_param"], "confidence": p["confidence"]}
        for p in gen_payloads
    ]

    async with AsyncClient(
        transport=ASGITransport(app=fuzzer_mod.app), base_url="http://test"
    ) as client:
        fuzz_resp = await client.post("/test", json={
            "url": "https://target.com",
            "payloads": fuzzer_payloads,
            "verify_execution": False,
            "timeout": 5000,
        })
    assert fuzz_resp.status_code == 200
    results = fuzz_resp.json()["results"]

    # verify the full pipeline produced a vulnerability
    assert len(results) >= 1
    vuln_results = [r for r in results if r["vuln"]]
    assert len(vuln_results) >= 1
    assert vuln_results[0]["payload"] == gen_payloads[0]["payload"]
    assert vuln_results[0]["reflected"] is True


# ── test: schema contract validation ─────────────────────────

def test_context_output_matches_payloadgen_input_schema():
    """verify the pydantic models are compatible between modules"""
    from shared.schemas import ParamContext, GenerateRequest

    # create a context output like the context module would return
    context_output = {
        "q": ParamContext(
            reflects_in="html_text",
            allowed_chars=["<", ">"],
            context_confidence=0.9,
        ),
    }

    # feed it into GenerateRequest — should not raise
    req = GenerateRequest(
        contexts=context_output,
        waf="none",
        max_payloads=50,
    )
    assert req.contexts["q"].reflects_in == "html_text"


def test_payloadgen_output_matches_fuzzer_input_schema():
    """verify GeneratedPayload can be converted to FuzzPayload"""
    from shared.schemas import GeneratedPayload, FuzzPayload

    # create a payload-gen output
    gen = GeneratedPayload(
        payload="<script>alert(1)</script>",
        target_param="q",
        context="html_text",
        confidence=0.9,
        waf_bypass=False,
    )

    # convert to fuzzer input — should not raise
    fuzz_payload = FuzzPayload(
        payload=gen.payload,
        target_param=gen.target_param,
        confidence=gen.confidence,
    )
    assert fuzz_payload.payload == gen.payload
    assert fuzz_payload.target_param == gen.target_param
