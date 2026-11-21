"""Structured JSON audit log. Never logs raw prompts: only hashes, scores and
decisions, so the audit trail itself does not become a PII store."""

from __future__ import annotations

import hashlib
import json
import logging
import sys
import time

_logger = logging.getLogger("llm_gateway.audit")
if not _logger.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(_h)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def audit(event: str, **fields: object) -> None:
    _logger.info(json.dumps({"ts": round(time.time(), 3), "event": event, **fields}, default=str))
