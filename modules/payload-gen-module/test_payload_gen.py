"""
tests for the payload-gen module fastapi app.
mocks the payload bank and pipeline functions.
"""

import sys
import os
import importlib.util
from unittest.mock import patch, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

# load local app.py under a unique module name to avoid cache collisions
_dir = os.path.dirname(__file__)
_spec = importlib.util.spec_from_file_location("payload_gen_app", os.path.join(_dir, "app.py"))
_mod = importlib.util.module_from_spec(_spec)
sys.modules["payload_gen_app"] = _mod
# allow app.py's own relative imports to resolve
if _dir not in sys.path:
    sys.path.insert(0, _dir)
parent = os.path.dirname(_dir)
if parent not in sys.path:
    sys.path.insert(0, parent)
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
