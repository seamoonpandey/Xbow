"""
shared pydantic schemas for inter-service communication
"""

from pydantic import BaseModel, Field


# ── context module ──────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    url: str
    params: list[str]
    waf: str = "none"


class ParamContext(BaseModel):
    reflects_in: str = "none"
    allowed_chars: list[str] = Field(default_factory=list)
    context_confidence: float = 0.0


# response is dict[str, ParamContext]


# ── payload-gen module ──────────────────────────────────────

class GenerateRequest(BaseModel):
    contexts: dict[str, ParamContext]
    waf: str = "none"
    max_payloads: int = 50


class GeneratedPayload(BaseModel):
    payload: str
    target_param: str
    context: str
    confidence: float
    waf_bypass: bool = False


class GenerateResponse(BaseModel):
    payloads: list[GeneratedPayload]


# ── fuzzer module ───────────────────────────────────────────

class FuzzPayload(BaseModel):
    payload: str
    target_param: str
    confidence: float = 0.0


class FuzzRequest(BaseModel):
    url: str
    payloads: list[FuzzPayload]
    verify_execution: bool = True
    timeout: int = 10000


class FuzzResult(BaseModel):
    payload: str
    target_param: str
    reflected: bool = False
    executed: bool = False
    vuln: bool = False
    type: str = ""
    evidence: dict = Field(default_factory=dict)


class FuzzResponse(BaseModel):
    results: list[FuzzResult]
