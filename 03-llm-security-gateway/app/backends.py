"""LLM backends. `mock` is deterministic so tests and demos need no API key;
`openai` talks to any OpenAI-compatible /v1/chat/completions endpoint
(OpenAI, Azure OpenAI, vLLM, Ollama, LiteLLM)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

import httpx


class Backend(Protocol):
    async def complete(self, messages: list[dict[str, str]]) -> str: ...


class MockBackend:
    async def complete(self, messages: list[dict[str, str]]) -> str:
        last = messages[-1]["content"] if messages else ""
        return f"[mock-llm] You asked: {last[:200]}"


def _upstream_api_key() -> str:
    """Prefer a mounted secret file (Kubernetes secret volume) over an env var,
    so the key doesn't leak through /proc/<pid>/environ, crash dumps or `env`."""
    key_file = os.environ.get("UPSTREAM_API_KEY_FILE")
    if key_file:
        return Path(key_file).read_text().strip()
    return os.environ.get("UPSTREAM_API_KEY", "")


class OpenAICompatibleBackend:
    def __init__(self, url: str, model: str, timeout: float = 30.0) -> None:
        if not url:
            raise ValueError("UPSTREAM_URL is required for the openai backend")
        self.url = url.rstrip("/") + "/v1/chat/completions"
        self.model = model
        self.timeout = timeout

    async def complete(self, messages: list[dict[str, str]]) -> str:
        headers = {"Authorization": f"Bearer {_upstream_api_key()}"}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                self.url,
                headers=headers,
                json={"model": self.model, "messages": messages, "max_tokens": 1024},
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]


def build_backend(kind: str, url: str, model: str) -> Backend:
    if kind == "mock":
        return MockBackend()
    if kind == "openai":
        return OpenAICompatibleBackend(url, model)
    raise ValueError(f"unknown backend: {kind}")
