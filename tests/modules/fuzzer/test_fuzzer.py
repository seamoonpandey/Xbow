"""
tests for the fuzzer module fastapi app.
mocks heavy dependencies (http_sender, reflection_checker, browser_verifier, dom_xss_scanner).
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock, PropertyMock

import pytest
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parents[3]
MODULE_DIR = ROOT / "modules" / "fuzzer-module"
MODULES_DIR = ROOT / "modules"

# load module app.py under a unique module name to avoid cache collisions
_spec = importlib.util.spec_from_file_location("fuzzer_app", MODULE_DIR / "app.py")
_mod = importlib.util.module_from_spec(_spec)
sys.modules["fuzzer_app"] = _mod
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
    assert data["service"] == "fuzzer"


@pytest.mark.anyio
async def test_fuzz_empty_payloads():
    """empty payloads list should return empty results"""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/fuzz", json={
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
        resp = await client.post("/fuzz", json={
            "payloads": [{"payload": "<script>", "target_param": "q"}],
        })
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_legacy_test_route_still_aliases_fuzz():
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
        resp = await client.post("/fuzz", json={
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
async def test_fuzz_forwards_auth_to_http_and_browser(
    mock_dom_scan, mock_verify, mock_reflect, mock_send
):
    storage_state = {
        "cookies": [
            {
                "name": "session",
                "value": "tok123",
                "domain": "example.com",
                "path": "/",
                "expires": -1,
                "httpOnly": True,
                "secure": True,
                "sameSite": "Lax",
            }
        ],
        "origins": [],
    }
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
            "exact_match": True,
            "status_code": 200,
            "reflection_position": "html_body",
            "context_snippet": "<html><script>alert(1)</script></html>",
        }
    ]
    mock_verify.return_value = []
    mock_dom_scan.return_value = MockScanResult([])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/fuzz", json={
            "url": "https://example.com",
            "payloads": [{"payload": "<script>alert(1)</script>", "target_param": "q", "confidence": 0.9}],
            "verify_execution": True,
            "timeout": 5000,
            "auth_cookie_header": "session=tok123",
            "auth_storage_state": storage_state,
        })

    assert resp.status_code == 200
    mock_send.assert_awaited_once()
    assert mock_send.await_args.kwargs["auth_cookie_header"] == "session=tok123"
    mock_verify.assert_awaited_once()
    assert mock_verify.await_args.kwargs["auth_cookie_header"] == "session=tok123"
    assert mock_verify.await_args.kwargs["auth_storage_state"] == storage_state


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
        resp = await client.post("/fuzz", json={
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


# ── Stored XSS mode tests ────────────────────────────────────────


@pytest.mark.anyio
@patch("fuzzer_app.send_stored_payloads", new_callable=AsyncMock)
@patch("fuzzer_app.check_reflection_batch")
@patch("fuzzer_app.verify_stored_form_payloads", new_callable=AsyncMock)
@patch("fuzzer_app.scan_response_body")
async def test_stored_xss_exact_match(
    mock_dom_scan, mock_verify_stored, mock_reflect, mock_send_stored
):
    """stored mode with exact match reflection → vuln=true"""
    mock_send_stored.return_value = MockSendBatch([
        MockSendResult(
            payload="<script>alert(1)</script>",
            target_param="comment",
            response_body="<html><script>alert(1)</script></html>",
            status_code=200,
        ),
    ])
    mock_reflect.return_value = [
        {
            "payload": "<script>alert(1)</script>",
            "target_param": "comment",
            "reflected": True,
            "exact_match": True,
            "status_code": 200,
            "reflection_position": "html_body",
            "context_snippet": "<html><script>alert(1)</script></html>",
        }
    ]
    mock_verify_stored.return_value = []
    mock_dom_scan.return_value = MockScanResult([])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/fuzz", json={
            "url": "https://example.com/submit",
            "payloads": [{"payload": "<script>alert(1)</script>", "target_param": "comment", "confidence": 0.9}],
            "verify_execution": False,
            "timeout": 5000,
            "stored_mode": True,
            "display_url": "https://example.com/display",
            "form_fields": {"csrf": "token123", "postId": "42"},
        })
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) >= 1
    stored_vulns = [r for r in results if r["vuln"]]
    assert len(stored_vulns) >= 1
    assert stored_vulns[0]["type"] == "stored_xss"


@pytest.mark.anyio
@patch("fuzzer_app.send_stored_payloads", new_callable=AsyncMock)
@patch("fuzzer_app.check_reflection_batch")
@patch("fuzzer_app.verify_stored_form_payloads", new_callable=AsyncMock)
@patch("fuzzer_app.scan_response_body")
async def test_stored_xss_decoded_only_falls_through_to_browser(
    mock_dom_scan, mock_verify_stored, mock_reflect, mock_send_stored
):
    """when HTTP stored path finds nothing, browser verifier is tried"""
    mock_send_stored.return_value = MockSendBatch([
        MockSendResult(
            payload="<script>alert(1)</script>",
            target_param="comment",
            response_body="<html>safe</html>",
            status_code=200,
        ),
    ])
    mock_reflect.return_value = [
        {
            "payload": "<script>alert(1)</script>",
            "target_param": "comment",
            "reflected": False,
            "status_code": 200,
        }
    ]
    # Browser verifier finds execution
    mock_verify_stored.return_value = [
        MagicMock(
            payload="<script>alert(1)</script>",
            target_param="comment",
            executed=True,
            dialog_triggered=True,
            dialog_message="1",
        )
    ]
    mock_dom_scan.return_value = MockScanResult([])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/fuzz", json={
            "url": "https://example.com/submit",
            "payloads": [{"payload": "<script>alert(1)</script>", "target_param": "comment", "confidence": 0.9}],
            "verify_execution": False,
            "timeout": 5000,
            "stored_mode": True,
            "display_url": "https://example.com/display",
            "form_fields": {"csrf": "token123"},
        })
    assert resp.status_code == 200
    results = resp.json()["results"]
    # Should have dom_stored_xss from browser verification
    dom_stored = [r for r in results if r["type"] == "dom_stored_xss"]
    assert len(dom_stored) >= 1
    assert dom_stored[0]["vuln"] is True


# ── Fragment injection tests ─────────────────────────────────────


@pytest.mark.anyio
@patch("fuzzer_app.fetch_url", new_callable=AsyncMock)
@patch("fuzzer_app.verify_payloads", new_callable=AsyncMock)
@patch("fuzzer_app.scan_response_body")
async def test_fragment_injection_pathway(
    mock_dom_scan, mock_verify, mock_fetch
):
    """fragment payloads skip HTTP send, go directly to browser verify"""
    # Non-fragment payloads to confirm the normal pipeline also runs
    mock_fetch.return_value = MagicMock(
        response_body="<html>base page</html>",
        status_code=200,
        error=None,
    )
    mock_dom_scan.return_value = MockScanResult([])
    mock_verify.return_value = [
        MagicMock(
            payload="<svg onload=alert(1)>",
            target_param="__fragment__",
            executed=True,
            dialog_triggered=True,
            dialog_message="1",
        )
    ]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/fuzz", json={
            "url": "https://example.com",
            "payloads": [{"payload": "<svg onload=alert(1)>", "target_param": "__fragment__", "confidence": 0.9}],
            "verify_execution": True,
            "timeout": 5000,
        })
    assert resp.status_code == 200
    results = resp.json()["results"]
    frag_results = [r for r in results if r["target_param"] == "__fragment__"]
    assert len(frag_results) >= 1
    assert frag_results[0]["vuln"] is True
    assert frag_results[0]["type"] == "dom_xss"
    assert frag_results[0]["evidence"]["reflection_position"] == "fragment"
    assert frag_results[0]["evidence"]["browser_alert_triggered"] is True


# ── DOM-only scan mode ───────────────────────────────────────────


@pytest.mark.anyio
@patch("fuzzer_app.fetch_url", new_callable=AsyncMock)
@patch("fuzzer_app.scan_response_body")
async def test_dom_only_scan_empty_payloads(
    mock_dom_scan, mock_fetch
):
    """empty payloads list triggers DOM-only scan"""
    mock_fetch.return_value = MagicMock(
        response_body="<html><script>eval(location.hash)</script></html>",
        status_code=200,
        error=None,
    )
    # findings_to_results accesses DomXssFinding attributes
    import types
    mock_finding = types.SimpleNamespace(
        has_tainted_source=True,
        source_name="location.hash",
        sink_name="eval",
        sink_type="dom_xss",
        severity="high",
        line_number=5,
        line_content="eval(location.hash)",
        confidence="high",
        script_url="https://example.com",
        fragment_dependent=True,
        suggested_payload="",
    )
    mock_dom_scan.return_value = MockScanResult([mock_finding])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/fuzz", json={
            "url": "https://example.com",
            "payloads": [],
            "verify_execution": False,
            "timeout": 5000,
        })
    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data


# ── Metadata and training data ───────────────────────────────────


@pytest.mark.anyio
@patch("fuzzer_app.send_payloads", new_callable=AsyncMock)
@patch("fuzzer_app.check_reflection_batch")
@patch("fuzzer_app.verify_payloads", new_callable=AsyncMock)
@patch("fuzzer_app.scan_response_body")
@patch("fuzzer_app.collect_batch_training_samples")
async def test_fuzz_with_metadata_for_training(
    mock_collect, mock_dom_scan, mock_verify, mock_reflect, mock_send
):
    """training metadata (context, waf, allowed_chars) is forwarded"""
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
            "exact_match": True,
            "status_code": 200,
            "reflection_position": "html_body",
            "context_snippet": "<html><script>alert(1)</script></html>",
        }
    ]
    mock_verify.return_value = []
    mock_dom_scan.return_value = MockScanResult([])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/fuzz", json={
            "url": "https://example.com",
            "payloads": [{"payload": "<script>alert(1)</script>", "target_param": "q", "confidence": 0.9}],
            "verify_execution": False,
            "timeout": 5000,
            "context": "script_injection",
            "waf": "cloudflare",
            "allowed_chars": ["<", ">"],
        })
    assert resp.status_code == 200
    # verify training data collection was called
    mock_collect.assert_called_once()
