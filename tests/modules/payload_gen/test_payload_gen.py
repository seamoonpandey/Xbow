"""
tests for the payload-gen module fastapi app.
mocks the payload bank and pipeline functions.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parents[3]
MODULE_DIR = ROOT / "modules" / "payload-gen-module"
MODULES_DIR = ROOT / "modules"

# load module app.py under a unique module name to avoid cache collisions
_spec = importlib.util.spec_from_file_location("payload_gen_app", MODULE_DIR / "app.py")
_mod = importlib.util.module_from_spec(_spec)
sys.modules["payload_gen_app"] = _mod
# allow app.py's own relative imports to resolve
for path in (MODULE_DIR, MODULES_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
_spec.loader.exec_module(_mod)
app = _mod.app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_health_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "payload-gen"
    assert "bank_loaded" in data


@pytest.mark.anyio
async def test_generate_empty_contexts():
    """empty contexts should return empty payloads list"""
    # ensure bank is loaded (mock it)
    import payload_gen_app as app_module
    app_module.bank = MagicMock()
    app_module.bank.size = 100

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/generate", json={
            "contexts": {},
            "waf": "none",
            "max_payloads": 10,
        })
    assert resp.status_code == 200
    data = resp.json()
    assert data["payloads"] == []


@pytest.mark.anyio
async def test_generate_no_bank_returns_503():
    """when bank is not loaded, should return 503"""
    import payload_gen_app as app_module
    original_bank = app_module.bank
    app_module.bank = None

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post("/generate", json={
                "contexts": {
                    "q": {"reflects_in": "html_text", "allowed_chars": ["<", ">"], "context_confidence": 0.9}
                },
                "waf": "none",
                "max_payloads": 10,
            })
        assert resp.status_code == 503
    finally:
        app_module.bank = original_bank


@pytest.mark.anyio
async def test_generate_empty_bank_returns_503():
    """when bank is loaded but empty, should return 503"""
    import payload_gen_app as app_module
    original_bank = app_module.bank
    app_module.bank = MagicMock()
    app_module.bank.size = 0

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/generate",
                json={
                    "contexts": {
                        "q": {
                            "reflects_in": "html_text",
                            "allowed_chars": ["<", ">"],
                            "context_confidence": 0.9,
                        }
                    },
                    "waf": "none",
                    "max_payloads": 10,
                },
            )
        assert resp.status_code == 503
    finally:
        app_module.bank = original_bank


@pytest.mark.anyio
@patch("payload_gen_app.select_payloads")
@patch("payload_gen_app.mutate_payloads")
@patch("payload_gen_app.rank_payloads")
async def test_generate_with_context(mock_rank, mock_mutate, mock_select):
    """pipeline: select → mutate → rank → return"""
    import payload_gen_app as app_module
    app_module.bank = MagicMock()
    app_module.bank.size = 100

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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/generate", json={
            "contexts": {
                "q": {"reflects_in": "html_text", "allowed_chars": ["<", ">"], "context_confidence": 0.9}
            },
            "waf": "none",
            "max_payloads": 10,
        })
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["payloads"]) == 2
    assert data["payloads"][0]["target_param"] == "q"
    assert data["payloads"][0]["context"] == "html_text"


@pytest.mark.anyio
async def test_generate_missing_body():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/generate")
    assert resp.status_code == 422


# ── /ranker/info endpoint ────────────────────────────────────────


@pytest.mark.anyio
async def test_ranker_info_endpoint():
    """ranker/info returns model status and feature importance"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/ranker/info")
    assert resp.status_code == 200
    data = resp.json()
    assert "model_loaded" in data
    assert "ranker_type" in data
    assert "feature_importance" in data


# ── WAF bypass (obfuscation) path ────────────────────────────────


@pytest.mark.anyio
@patch("payload_gen_app.select_payloads")
@patch("payload_gen_app.mutate_payloads")
@patch("payload_gen_app.obfuscate_payloads")
@patch("payload_gen_app.rank_payloads")
async def test_generate_with_waf_bypass(
    mock_rank, mock_obfuscate, mock_mutate, mock_select
):
    """WAF bypass triggers obfuscation pipeline"""
    import payload_gen_app as app_module
    app_module.bank = MagicMock()
    app_module.bank.size = 100

    mock_select.return_value = [
        {"payload": "<script>alert(1)</script>", "technique": "basic"},
    ]
    mock_mutate.return_value = [
        {"payload": "<script>alert(1)</script>", "technique": "basic"},
    ]
    mock_obfuscate.return_value = [
        {"payload": "<script>alert(1)</script>", "technique": "obfuscated:cloudflare"},
        {"payload": "<ScRiPt>alert(1)</ScRiPt>", "technique": "obfuscated:cloudflare"},
    ]
    mock_rank.return_value = [
        {"payload": "<script>alert(1)</script>", "technique": "obfuscated:cloudflare", "score": 0.85},
        {"payload": "<ScRiPt>alert(1)</ScRiPt>", "technique": "obfuscated:cloudflare", "score": 0.75},
    ]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/generate", json={
            "contexts": {
                "q": {"reflects_in": "html_body", "allowed_chars": ["<", ">"], "context_confidence": 0.9}
            },
            "waf": "cloudflare",
            "max_payloads": 10,
        })
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["payloads"]) == 2
    # obfuscation should be called since waf!="none"
    mock_obfuscate.assert_called_once()
    # WAF bypass payloads should have waf_bypass=True
    for p in data["payloads"]:
        assert p["waf_bypass"] is True
        assert "obfuscated" in p["technique"]


# ── Budget per param ─────────────────────────────────────────────


@pytest.mark.anyio
@patch("payload_gen_app.select_payloads")
@patch("payload_gen_app.mutate_payloads")
@patch("payload_gen_app.rank_payloads")
async def test_generate_min_budget_per_param(
    mock_rank, mock_mutate, mock_select
):
    """each param gets at least 10 payload budget"""
    import payload_gen_app as app_module
    app_module.bank = MagicMock()
    app_module.bank.size = 100

    mock_select.return_value = [
        {"payload": f"payload_{i}", "technique": "basic"} for i in range(15)
    ]
    mock_mutate.side_effect = lambda payloads, **kw: payloads
    mock_rank.side_effect = lambda payloads, **kw: [
        {**p, "score": 0.5} for p in payloads
    ]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/generate", json={
            "contexts": {
                "q": {"reflects_in": "html_body", "allowed_chars": ["<", ">"], "context_confidence": 0.9},
            },
            "waf": "none",
            "max_payloads": 5,  # less than 10 → budget bumps to 10
        })
    assert resp.status_code == 200
    data = resp.json()
    # With 1 param, budget=max(5//1, 10)=10, selected 15, ranked 10 — limited to 5 total
    assert len(data["payloads"]) == 5  # max_payloads=5 final limit


# ── max_payloads limiting ────────────────────────────────────────


@pytest.mark.anyio
@patch("payload_gen_app.select_payloads")
@patch("payload_gen_app.mutate_payloads")
@patch("payload_gen_app.rank_payloads")
async def test_generate_max_payloads_limit(
    mock_rank, mock_mutate, mock_select
):
    """total payloads are capped by max_payloads"""
    import payload_gen_app as app_module
    app_module.bank = MagicMock()
    app_module.bank.size = 100

    mock_select.return_value = [
        {"payload": f"payload_{i}", "technique": "basic"} for i in range(30)
    ]
    mock_mutate.side_effect = lambda payloads, **kw: payloads
    mock_rank.side_effect = lambda payloads, **kw: [
        {**p, "score": 0.5} for p in payloads
    ]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/generate", json={
            "contexts": {
                "q": {"reflects_in": "html_body", "allowed_chars": ["<", ">"], "context_confidence": 0.9},
            },
            "waf": "none",
            "max_payloads": 3,
        })
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["payloads"]) == 3  # capped by max_payloads


# ── Technique and severity fields ────────────────────────────────


@pytest.mark.anyio
@patch("payload_gen_app.select_payloads")
@patch("payload_gen_app.mutate_payloads")
@patch("payload_gen_app.rank_payloads")
async def test_generated_payload_has_technique_and_severity(
    mock_rank, mock_mutate, mock_select
):
    """generated payloads include technique and severity fields"""
    import payload_gen_app as app_module
    app_module.bank = MagicMock()
    app_module.bank.size = 100

    mock_select.return_value = [
        {"payload": "<script>alert(1)</script>", "technique": "original"},
    ]
    mock_mutate.return_value = [
        {"payload": "<script>alert(1)</script>", "technique": "original", "severity": "high"},
        {"payload": "<ScRiPt>alert(1)</ScRiPt>", "technique": "case_swap", "severity": "medium"},
    ]
    mock_rank.return_value = [
        {"payload": "<script>alert(1)</script>", "technique": "original", "score": 0.9, "severity": "high"},
        {"payload": "<ScRiPt>alert(1)</ScRiPt>", "technique": "case_swap", "score": 0.7, "severity": "medium"},
    ]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/generate", json={
            "contexts": {
                "q": {"reflects_in": "html_body", "allowed_chars": ["<", ">"], "context_confidence": 0.9}
            },
            "waf": "none",
            "max_payloads": 10,
        })
    assert resp.status_code == 200
    data = resp.json()
    for p in data["payloads"]:
        assert "technique" in p
        assert "severity" in p
        assert p["technique"] in ("original", "case_swap")
        assert p["severity"] in ("high", "medium", "low")
