"""
tests for the fuzzer module fastapi app.
mocks heavy dependencies (http_sender, reflection_checker, browser_verifier, dom_xss_scanner).
"""

import sys
import os
import importlib.util
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

# load local app.py under a unique module name to avoid cache collisions
_dir = os.path.dirname(__file__)
_spec = importlib.util.spec_from_file_location("fuzzer_app", os.path.join(_dir, "app.py"))
_mod = importlib.util.module_from_spec(_spec)
sys.modules["fuzzer_app"] = _mod
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
    assert data["service"] == "fuzzer"


@pytest.mark.anyio
async def test_fuzz_empty_payloads():
    """empty payloads list should return empty results"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/test", json={
            "url": "https://example.com",
            "payloads": [],
            "verify_execution": True,
            "timeout": 5000,
        })
    assert resp.status_code == 200
    assert resp.json()["results"] == []


@pytest.mark.anyio
async def test_fuzz_missing_url():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/test", json={
            "payloads": [{"payload": "<script>", "target_param": "q"}],
        })
    assert resp.status_code == 422


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
@patch("fuzzer_app.send_payloads", new_callable=AsyncMock)
@patch("fuzzer_app.check_reflection_batch")
@patch("fuzzer_app.verify_payloads", new_callable=AsyncMock)
@patch("fuzzer_app.scan_response_body")
async def test_fuzz_reflected_payload(
    mock_dom_scan, mock_verify, mock_reflect, mock_send
):
    """a reflected payload should appear in results"""
    mock_send.return_value = MockSendBatch([
        MockSendResult(
            payload="<script>alert(1)</script>",
            target_param="q",
            response_body="<html><script>alert(1)</script></html>",
            status_code=200,
        ),
    ])
    mock_reflect.return_value = [
        {
            "payload": "<script>alert(1)</script>",
            "target_param": "q",
            "reflected": True,
            "status_code": 200,
            "reflection_position": "body",
            "context_snippet": "<html><script>alert(1)</script></html>",
        }
    ]
    mock_verify.return_value = []
    mock_dom_scan.return_value = MockScanResult([])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/test", json={
            "url": "https://example.com",
            "payloads": [{"payload": "<script>alert(1)</script>", "target_param": "q", "confidence": 0.9}],
            "verify_execution": False,
            "timeout": 5000,
        })
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) >= 1
    reflected_results = [r for r in results if r["reflected"]]
    assert len(reflected_results) >= 1
    assert reflected_results[0]["vuln"] is True  # reflected + no verify = vuln


@pytest.mark.anyio
@patch("fuzzer_app.send_payloads", new_callable=AsyncMock)
@patch("fuzzer_app.check_reflection_batch")
@patch("fuzzer_app.verify_payloads", new_callable=AsyncMock)
@patch("fuzzer_app.scan_response_body")
async def test_fuzz_non_reflected_not_vuln(
    mock_dom_scan, mock_verify, mock_reflect, mock_send
):
    """a non-reflected payload should not be marked as vuln"""
    mock_send.return_value = MockSendBatch([
        MockSendResult(
            payload="<script>alert(1)</script>",
            target_param="q",
            response_body="<html>safe</html>",
            status_code=200,
        ),
    ])
    mock_reflect.return_value = [
        {
            "payload": "<script>alert(1)</script>",
            "target_param": "q",
            "reflected": False,
            "status_code": 200,
        }
    ]
    mock_verify.return_value = []
    mock_dom_scan.return_value = MockScanResult([])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/test", json={
            "url": "https://example.com",
            "payloads": [{"payload": "<script>alert(1)</script>", "target_param": "q", "confidence": 0.9}],
            "verify_execution": True,
            "timeout": 5000,
        })
    assert resp.status_code == 200
    results = resp.json()["results"]
    for r in results:
        if r["payload"] == "<script>alert(1)</script>":
            assert r["vuln"] is False
