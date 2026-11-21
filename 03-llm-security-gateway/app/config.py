from __future__ import annotations

import os
from dataclasses import dataclass, field


def _csv(name: str, default: str) -> set[str]:
    return {x.strip().lower() for x in os.getenv(name, default).split(",") if x.strip()}


@dataclass(frozen=True)
class Settings:
    # "block" rejects risky prompts; "flag" lets them through but marks them in the audit log.
    injection_mode: str = field(default_factory=lambda: os.getenv("INJECTION_MODE", "block"))
    injection_threshold: float = field(default_factory=lambda: float(os.getenv("INJECTION_THRESHOLD", "0.5")))
    max_prompt_chars: int = field(default_factory=lambda: int(os.getenv("MAX_PROMPT_CHARS", "8000")))
    rate_limit_per_minute: int = field(default_factory=lambda: int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")))
    allowed_output_domains: set[str] = field(
        default_factory=lambda: _csv("ALLOWED_OUTPUT_DOMAINS", "docs.python.org,kubernetes.io,owasp.org")
    )
    backend: str = field(default_factory=lambda: os.getenv("LLM_BACKEND", "mock"))
    upstream_url: str = field(default_factory=lambda: os.getenv("UPSTREAM_URL", ""))
    upstream_model: str = field(default_factory=lambda: os.getenv("UPSTREAM_MODEL", "gpt-4o-mini"))
    # API keys are hashed at rest in the env var as sha256 hex digests.
    api_key_hashes: set[str] = field(default_factory=lambda: _csv("API_KEY_SHA256", ""))


def get_settings() -> Settings:
    return Settings()
