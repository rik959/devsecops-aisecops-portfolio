"""PII detection and redaction (LLM02 / LLM06: sensitive information disclosure).

Redacts before a prompt leaves the trust boundary and again on model output.
Card numbers are Luhn-validated to cut false positives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PATTERNS: dict[str, re.Pattern[str]] = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "AWS_ACCESS_KEY": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "CARD": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "IPV4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "PHONE_IN": re.compile(r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)"),
    "AADHAAR": re.compile(r"(?<!\d)(?<!\d[ -])[2-9]\d{3}\s?\d{4}\s?\d{4}(?![ -]?\d)"),
}

# Order matters: longer / more specific entities first so they win overlaps.
ORDER = ["PRIVATE_KEY", "JWT", "AWS_ACCESS_KEY", "EMAIL", "CARD", "AADHAAR", "PHONE_IN", "IPV4"]


def luhn_ok(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass
class RedactionResult:
    text: str
    findings: dict[str, int]


def redact(text: str) -> RedactionResult:
    findings: dict[str, int] = {}
    for label in ORDER:
        pattern = PATTERNS[label]

        def _sub(m: re.Match[str], label: str = label) -> str:
            if label == "CARD" and not luhn_ok(m.group(0)):
                return m.group(0)
            findings[label] = findings.get(label, 0) + 1
            return f"[REDACTED_{label}]"

        text = pattern.sub(_sub, text)
    return RedactionResult(text=text, findings=findings)
