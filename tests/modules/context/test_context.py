"""
tests for the context module fastapi app.
uses httpx async client with fastapi testclient pattern.
mocks heavy dependencies (ai classifier, probe injector, char fuzzer).
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

ROOT = Path(__file__).resolve().parents[3]
MODULE_DIR = ROOT / "modules" / "context-module"

# load module app.py under a unique module name to avoid cache collisions
_spec = importlib.util.spec_from_file_location("context_app", MODULE_DIR / "app.py")
_mod = importlib.util.module_from_spec(_spec)
sys.modules["context_app"] = _mod
# allow app.py's own relative imports to resolve
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
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
    assert data["service"] == "context-module"
    assert "ai_model_loaded" in data


@pytest.mark.anyio
async def test_analyze_empty_params():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": [],
        })
    assert resp.status_code == 400


@pytest.mark.anyio
async def test_analyze_missing_url():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "params": ["q"],
        })
    assert resp.status_code == 422


@pytest.mark.anyio
@patch("context_app.inject_probes", new_callable=AsyncMock)
@patch("context_app.fuzz_chars", new_callable=AsyncMock)
@patch("context_app.analyze_reflection")
@patch("context_app.get_primary_context")
@patch("context_app.get_dom_context")
async def test_analyze_param_no_reflection(
    mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """when probe is not reflected, param gets default context"""
    mock_probes.return_value = {
        "q": {"marker": "rsp123", "body": "<html>hello</html>", "status_code": 200}
    }
    mock_reflection.return_value = []  # no reflection found

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["q"],
        })
    assert resp.status_code == 200
    data = resp.json()
    assert "q" in data
    assert data["q"]["reflects_in"] == "none"


@pytest.mark.anyio
@patch("context_app.inject_probes", new_callable=AsyncMock)
@patch("context_app.fuzz_chars", new_callable=AsyncMock)
@patch("context_app.analyze_reflection")
@patch("context_app.get_primary_context")
@patch("context_app.get_dom_context")
@patch("context_app.classifier")
async def test_analyze_param_with_reflection(
    mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """when probe is reflected and AI is confident, use AI context"""
    mock_probes.return_value = {
        "q": {"marker": "rsp123", "body": "<html>rsp123</html>", "status_code": 200}
    }
    mock_reflection.return_value = [
        {"position": "html_text", "context_snippet": "<p>rsp123</p>"}
    ]
    mock_primary.return_value = "html_text"
    mock_dom.return_value = "html_text"
    mock_classifier.classify.return_value = {
        "context_type": "html_text",
        "confidence": 0.95,
    }
    mock_fuzz.return_value = ["<", ">", "'", '"']

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["q"],
        })
    assert resp.status_code == 200
    data = resp.json()
    assert data["q"]["reflects_in"] == "html_text"
    assert data["q"]["context_confidence"] >= 0.8
    assert len(data["q"]["allowed_chars"]) > 0


# ── New schema fields: cookie_header, form_method, form_fields, display_url ──


@pytest.mark.anyio
@patch("context_app.inject_probes", new_callable=AsyncMock)
@patch("context_app.fuzz_chars", new_callable=AsyncMock)
@patch("context_app.analyze_reflection")
@patch("context_app.get_primary_context")
@patch("context_app.get_dom_context")
@patch("context_app.classifier")
async def test_analyze_accepts_cookie_header(
    mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """cookie_header field is accepted without error"""
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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["q"],
            "cookie_header": "session=tok123",
        })
    assert resp.status_code == 200
    data = resp.json()
    assert "q" in data


@pytest.mark.anyio
@patch("context_app.inject_probes", new_callable=AsyncMock)
@patch("context_app.fuzz_chars", new_callable=AsyncMock)
@patch("context_app.analyze_reflection")
@patch("context_app.get_primary_context")
@patch("context_app.get_dom_context")
@patch("context_app.classifier")
async def test_analyze_accepts_form_fields(
    mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """form_method and form_fields are accepted"""
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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["q"],
            "form_method": "POST",
            "form_fields": ["csrf", "postId"],
        })
    assert resp.status_code == 200
    data = resp.json()
    assert "q" in data


@pytest.mark.anyio
@patch("context_app.inject_probes", new_callable=AsyncMock)
@patch("context_app.fuzz_chars", new_callable=AsyncMock)
@patch("context_app.analyze_reflection")
@patch("context_app.get_primary_context")
@patch("context_app.get_dom_context")
@patch("context_app.classifier")
async def test_analyze_accepts_display_url(
    mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """display_url field is accepted"""
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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["q"],
            "display_url": "https://example.com/display",
        })
    assert resp.status_code == 200
    data = resp.json()
    assert "q" in data


# ── Fragment param analysis ──


@pytest.mark.anyio
@patch("context_app.inject_probes", new_callable=AsyncMock)
@patch("context_app.fuzz_chars", new_callable=AsyncMock)
@patch("context_app.analyze_reflection")
@patch("context_app.get_primary_context")
@patch("context_app.get_dom_context")
@patch("context_app.classifier")
@patch("context_app._has_hash_sink_signals")
async def test_fragment_param_with_hash_sink(
    mock_hash_sink, mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """fragment param with hash sink signals → heuristic html_body"""
    mock_probes.return_value = {
        "__fragment__": {"marker": "rsp123", "body": "<html>location.hash</html>", "status_code": 200},
    }
    mock_reflection.return_value = []  # no reflection (expected for fragment)
    mock_hash_sink.return_value = True  # has hash sink signals
    mock_fuzz.return_value = ["<", ">", '"', "'"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["__fragment__"],
        })
    assert resp.status_code == 200
    data = resp.json()
    assert "__fragment__" in data
    assert data["__fragment__"]["reflects_in"] == "html_body"
    assert data["__fragment__"]["context_confidence"] == 0.75
    assert len(data["__fragment__"]["allowed_chars"]) >= 7  # DEFAULT_FRAGMENT_ALLOWED_CHARS
    # fuzz_chars should NOT be called for fragment param
    mock_fuzz.assert_not_called()


@pytest.mark.anyio
@patch("context_app.inject_probes", new_callable=AsyncMock)
@patch("context_app.fuzz_chars", new_callable=AsyncMock)
@patch("context_app.analyze_reflection")
@patch("context_app.get_primary_context")
@patch("context_app.get_dom_context")
@patch("context_app.classifier")
@patch("context_app._has_hash_sink_signals")
async def test_fragment_param_no_hash_sink(
    mock_hash_sink, mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """fragment param without hash sink signals → none"""
    mock_probes.return_value = {
        "__fragment__": {"marker": "rsp123", "body": "<html>no hash sink</html>", "status_code": 200},
    }
    mock_reflection.return_value = []
    mock_hash_sink.return_value = False  # no hash sink signals

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["__fragment__"],
        })
    assert resp.status_code == 200
    data = resp.json()
    assert data["__fragment__"]["reflects_in"] == "none"
    assert data["__fragment__"]["context_confidence"] == 0.0


# ── AI classifier: low confidence fallback path ──


@pytest.mark.anyio
@patch("context_app.inject_probes", new_callable=AsyncMock)
@patch("context_app.fuzz_chars", new_callable=AsyncMock)
@patch("context_app.analyze_reflection")
@patch("context_app.get_primary_context")
@patch("context_app.get_dom_context")
@patch("context_app.classifier")
async def test_ai_low_confidence_falls_back_to_dom(
    mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """when AI confidence < 0.8, fallback to DOM context"""
    mock_probes.return_value = {
        "q": {"marker": "rsp123", "body": "<html>rsp123</html>", "status_code": 200},
    }
    mock_reflection.return_value = [
        {"position": "html_text", "context_snippet": "<p>rsp123</p>"}
    ]
    mock_primary.return_value = "html_text"
    mock_dom.return_value = "html_body"  # DOM says html_body
    mock_classifier.classify.return_value = {
        "context_type": "attribute",
        "confidence": 0.6,  # low confidence
    }
    mock_fuzz.return_value = ["<", ">", "'", '"']

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["q"],
        })
    assert resp.status_code == 200
    data = resp.json()
    # DOM context should win (dom_context != "none", so use it)
    assert data["q"]["reflects_in"] == "html_body"
    assert data["q"]["context_confidence"] >= 0.6  # max(0.7, 0.6)


@pytest.mark.anyio
@patch("context_app.inject_probes", new_callable=AsyncMock)
@patch("context_app.fuzz_chars", new_callable=AsyncMock)
@patch("context_app.analyze_reflection")
@patch("context_app.get_primary_context")
@patch("context_app.get_dom_context")
@patch("context_app.classifier")
async def test_ai_low_confidence_falls_back_to_regex(
    mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """when both AI and DOM are low, fallback to regex"""
    mock_probes.return_value = {
        "q": {"marker": "rsp123", "body": "<html>rsp123</html>", "status_code": 200},
    }
    mock_reflection.return_value = [
        {"position": "html_text", "context_snippet": "<p>rsp123</p>"}
    ]
    mock_primary.return_value = "html_text"  # regex context
    mock_dom.return_value = "none"  # DOM says none
    mock_classifier.classify.return_value = {
        "context_type": "attribute",
        "confidence": 0.3,  # very low confidence
    }
    mock_fuzz.return_value = ["<", ">"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["q"],
        })
    assert resp.status_code == 200
    data = resp.json()
    # regex context wins
    assert data["q"]["reflects_in"] == "html_text"


# ── DOM context override: js_string and url not overridden by AI ──


@pytest.mark.anyio
@patch("context_app.inject_probes", new_callable=AsyncMock)
@patch("context_app.fuzz_chars", new_callable=AsyncMock)
@patch("context_app.analyze_reflection")
@patch("context_app.get_primary_context")
@patch("context_app.get_dom_context")
@patch("context_app.classifier")
async def test_dom_js_string_not_overridden_by_ai(
    mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """DOM js_string is highly specific — AI should NOT override to generic attribute"""
    mock_probes.return_value = {
        "q": {"marker": "rsp123", "body": "<html>rsp123</html>", "status_code": 200},
    }
    mock_reflection.return_value = [
        {"position": "js_string", "context_snippet": "'rsp123'"}
    ]
    mock_primary.return_value = "js_string"
    mock_dom.return_value = "js_string"  # DOM says js_string
    mock_classifier.classify.return_value = {
        "context_type": "attribute",  # AI incorrectly says attribute
        "confidence": 0.95,  # high confidence
    }
    mock_fuzz.return_value = ["<", ">", "'", '"']

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["q"],
        })
    assert resp.status_code == 200
    data = resp.json()
    # Should keep js_string, not override to attribute
    assert data["q"]["reflects_in"] == "js_string"
    assert data["q"]["context_confidence"] >= 0.9


@pytest.mark.anyio
@patch("context_app.inject_probes", new_callable=AsyncMock)
@patch("context_app.fuzz_chars", new_callable=AsyncMock)
@patch("context_app.analyze_reflection")
@patch("context_app.get_primary_context")
@patch("context_app.get_dom_context")
@patch("context_app.classifier")
async def test_dom_url_not_overridden_by_ai(
    mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """DOM URL context is highly specific — AI should NOT override to generic attribute"""
    mock_probes.return_value = {
        "q": {"marker": "rsp123", "body": "<a href='rsp123'>link</a>", "status_code": 200},
    }
    mock_reflection.return_value = [
        {"position": "url", "context_snippet": "<a href='rsp123'>"}
    ]
    mock_primary.return_value = "url"
    mock_dom.return_value = "url"
    mock_classifier.classify.return_value = {
        "context_type": "attribute",
        "confidence": 0.98,
    }
    mock_fuzz.return_value = ['"', "'", "#", ":"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["q"],
        })
    assert resp.status_code == 200
    data = resp.json()
    assert data["q"]["reflects_in"] == "url"
    assert data["q"]["context_confidence"] >= 0.9


# ── Heuristic override: element/event indicators force html_body ──


@pytest.mark.anyio
@patch("context_app.inject_probes", new_callable=AsyncMock)
@patch("context_app.fuzz_chars", new_callable=AsyncMock)
@patch("context_app.analyze_reflection")
@patch("context_app.get_primary_context")
@patch("context_app.get_dom_context")
@patch("context_app.classifier")
async def test_heuristic_override_onerror_forces_html_body(
    mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """onerror in response body → force html_body"""
    mock_probes.return_value = {
        "q": {"marker": "rsp123", "body": "<img src=x onerror=alert(1) rsp123>", "status_code": 200},
    }
    mock_reflection.return_value = [
        {"position": "attribute", "context_snippet": 'onerror="rsp123"'}
    ]
    mock_primary.return_value = "attribute"
    mock_dom.return_value = "attribute"
    mock_classifier.classify.return_value = {
        "context_type": "attribute",
        "confidence": 0.75,
    }
    mock_fuzz.return_value = ["<", ">"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["q"],
        })
    assert resp.status_code == 200
    data = resp.json()
    # onerror in combined text → heuristic overrides to html_body
    assert data["q"]["reflects_in"] == "html_body"
    assert data["q"]["context_confidence"] >= 0.85


@pytest.mark.anyio
@patch("context_app.inject_probes", new_callable=AsyncMock)
@patch("context_app.fuzz_chars", new_callable=AsyncMock)
@patch("context_app.analyze_reflection")
@patch("context_app.get_primary_context")
@patch("context_app.get_dom_context")
@patch("context_app.classifier")
async def test_heuristic_override_innerhtml_forces_html_body(
    mock_classifier, mock_dom, mock_primary, mock_reflection, mock_fuzz, mock_probes
):
    """innerHTML in response body → force html_body"""
    mock_probes.return_value = {
        "q": {"marker": "rsp123", "body": "<div id=x>innerHTML='rsp123'</div>", "status_code": 200},
    }
    mock_reflection.return_value = [
        {"position": "attribute", "context_snippet": "innerHTML='rsp123'"}
    ]
    mock_primary.return_value = "attribute"
    mock_dom.return_value = "attribute"
    mock_classifier.classify.return_value = {
        "context_type": "attribute",
        "confidence": 0.9,
    }
    mock_fuzz.return_value = ["<", ">"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/analyze", json={
            "url": "https://example.com",
            "params": ["q"],
        })
    assert resp.status_code == 200
    data = resp.json()
    assert data["q"]["reflects_in"] == "html_body"
    assert data["q"]["context_confidence"] >= 0.85
