"""LLM Security Gateway: a policy-enforcing reverse proxy in front of any LLM.

Request path:
  auth -> rate limit -> size check -> PII redaction -> injection scoring
       -> backend call -> output sanitisation -> audit log -> response
"""

from __future__ import annotations

import hmac
import time
import uuid
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, Field

from .audit import audit, sha256
from .backends import Backend, build_backend
from .config import Settings, get_settings
from .guards import redact, sanitise_output, score_text
from .ratelimit import TokenBucketLimiter

app = FastAPI(title="LLM Security Gateway", version="1.0.0")

_settings = get_settings()
_limiter = TokenBucketLimiter(_settings.rate_limit_per_minute)
_backend: Backend = build_backend(_settings.backend, _settings.upstream_url, _settings.upstream_model)
# RED metrics (consumed by 06-observability-sre SLO rules) + security counters.
HTTP_REQUESTS = Counter("http_requests", "HTTP requests", ["handler", "method", "status"])
HTTP_LATENCY = Histogram(
    "http_request_duration_seconds", "HTTP request latency", ["handler"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8, 16, 32),
)
CHAT_REQUESTS = Counter("llm_gateway_requests", "Chat requests received")
BLOCKED_INJECTION = Counter("llm_gateway_blocked_injection", "Prompts blocked as injection")
BLOCKED_RATE_LIMIT = Counter("llm_gateway_blocked_rate_limit", "Requests rejected by rate limiting")
PII_REDACTIONS = Counter("llm_gateway_pii_redactions", "PII/secret entities redacted", ["entity"])
OUTPUT_ACTIONS = Counter("llm_gateway_output_actions", "Output sanitisation actions", ["action"])


class Message(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str = Field(max_length=100_000)


class ChatRequest(BaseModel):
    messages: list[Message] = Field(min_length=1, max_length=50)


class ChatResponse(BaseModel):
    request_id: str
    content: str
    injection_score: float
    redactions: dict[str, int]
    output_actions: list[str]


def settings_dep() -> Settings:
    return _settings


def identity(
    request: Request,
    x_api_key: str | None = Header(default=None),
    settings: Settings = Depends(settings_dep),
) -> str:
    """API-key auth with constant-time comparison against stored SHA-256 hashes.
    If no keys are configured (local dev), fall back to client IP identity."""
    if settings.api_key_hashes:
        if not x_api_key:
            raise HTTPException(status_code=401, detail="missing X-API-Key")
        digest = sha256(x_api_key)
        if not any(hmac.compare_digest(digest, h) for h in settings.api_key_hashes):
            raise HTTPException(status_code=403, detail="invalid API key")
        return "key:" + digest[:12]
    return "ip:" + (request.client.host if request.client else "unknown")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    start = time.perf_counter()
    response: Response = await call_next(request)
    route = request.scope.get("route")
    handler = getattr(route, "path", "unmatched")
    HTTP_REQUESTS.labels(handler, request.method, str(response.status_code)).inc()
    HTTP_LATENCY.labels(handler).observe(time.perf_counter() - start)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/v1/chat", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    who: str = Depends(identity),
    settings: Settings = Depends(settings_dep),
):
    request_id = str(uuid.uuid4())
    CHAT_REQUESTS.inc()

    allowed, retry_after = _limiter.allow(who)
    if not allowed:
        BLOCKED_RATE_LIMIT.inc()
        audit("rate_limited", request_id=request_id, who=who)
        return JSONResponse(
            status_code=429,
            content={"detail": "rate limit exceeded", "request_id": request_id},
            headers={"Retry-After": str(retry_after)},
        )

    total_chars = sum(len(m.content) for m in body.messages)
    if total_chars > settings.max_prompt_chars:
        raise HTTPException(status_code=413, detail=f"prompt exceeds {settings.max_prompt_chars} chars")

    # Only user-supplied turns are scored; the system prompt is operator-controlled.
    user_text = "\n".join(m.content for m in body.messages if m.role == "user")
    inj = score_text(user_text)

    redactions: dict[str, int] = {}
    clean_messages: list[dict[str, str]] = []
    for m in body.messages:
        r = redact(m.content)
        for k, v in r.findings.items():
            redactions[k] = redactions.get(k, 0) + v
        clean_messages.append({"role": m.role, "content": r.text})
    for entity, n in redactions.items():
        PII_REDACTIONS.labels(entity).inc(n)

    blocked = settings.injection_mode == "block" and inj.score >= settings.injection_threshold
    audit(
        "prompt_evaluated",
        request_id=request_id,
        who=who,
        prompt_sha256=sha256(user_text),
        injection_score=inj.score,
        rules=inj.matched,
        families=inj.families,
        redactions=redactions,
        decision="block" if blocked else "allow",
    )
    if blocked:
        BLOCKED_INJECTION.inc()
        raise HTTPException(
            status_code=400,
            detail={
                "error": "prompt_injection_detected",
                "request_id": request_id,
                "score": inj.score,
                "families": inj.families,
            },
        )

    raw = await _backend.complete(clean_messages)
    out = sanitise_output(raw, settings.allowed_output_domains)
    for action in out.actions:
        OUTPUT_ACTIONS.labels(action.split(":")[0]).inc()
    audit("response_sent", request_id=request_id, output_actions=out.actions)

    return ChatResponse(
        request_id=request_id,
        content=out.text,
        injection_score=inj.score,
        redactions=redactions,
        output_actions=out.actions,
    )
