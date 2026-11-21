"""Prompt-injection detection.

A layered, dependency-free detector:
  1. Normalisation (unicode NFKC, zero-width removal, lowercasing) to defeat
     trivial obfuscation.
  2. Weighted heuristic rules mapped to OWASP LLM01 attack families.
  3. Optional base64 payload decoding so encoded instructions are inspected too.

The detector returns a score in [0, 1] plus the matched rule ids, so the caller
can decide whether to block, flag, or allow. In production you would pair this
with a classifier model (e.g. a fine-tuned DeBERTa or Llama Guard); the
interface is designed so a model-based scorer can be plugged in alongside.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    family: str
    pattern: re.Pattern[str]
    weight: float


def _r(rule_id: str, family: str, regex: str, weight: float) -> Rule:
    return Rule(rule_id, family, re.compile(regex, re.IGNORECASE), weight)


RULES: tuple[Rule, ...] = (
    _r("INJ-001", "instruction_override",
       r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|system)\b.{0,20}\b(instructions?|rules?|prompts?|directions?)",
       0.6),
    _r("INJ-002", "instruction_override",
       r"\bnew (instructions?|rules?)\b\s*[:\-]", 0.35),
    _r("INJ-003", "system_prompt_exfiltration",
       r"\b(reveal|print|show|repeat|output|leak|tell me)\b.{0,40}\b(system prompt|hidden prompt|initial instructions|your instructions|developer message)",
       0.6),
    _r("INJ-004", "role_hijack",
       r"\b(you are now|act as|pretend to be|roleplay as)\b.{0,40}\b(dan|developer mode|jailbroken|unrestricted|no (rules|filters|restrictions))",
       0.6),
    _r("INJ-005", "role_hijack",
       r"\b(developer mode|jailbreak|do anything now)\b", 0.4),
    _r("INJ-006", "delimiter_injection",
       r"(<\|im_start\|>|<\|system\|>|\[/?INST\]|###\s*system|<<SYS>>)", 0.5),
    _r("INJ-007", "tool_abuse",
       r"\b(call|invoke|execute|run)\b.{0,30}\b(tool|function|shell|command)\b.{0,40}\b(without|bypass|skip)\b.{0,20}\b(confirmation|approval|check)",
       0.5),
    _r("INJ-008", "data_exfiltration",
       r"\b(send|post|upload|exfiltrate|forward)\b.{0,40}\b(to|at)\b.{0,10}(https?://|www\.|\S+@\S+\.)", 0.55),
    _r("INJ-009", "markdown_exfiltration",
       r"!\[[^\]]*\]\(https?://[^)]*\?(?:[^)]*=)", 0.55),
    _r("INJ-010", "safety_bypass",
       r"\b(disable|turn off|bypass)\b.{0,30}\b(safety|guardrails?|filters?|moderation|content policy)", 0.5),
)

B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)
    return re.sub(r"\s+", " ", text).strip()


def _decoded_payloads(text: str) -> list[str]:
    out: list[str] = []
    for candidate in B64_CANDIDATE.findall(text):
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded.isprintable():
            out.append(decoded)
    return out


@dataclass
class InjectionResult:
    score: float
    matched: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)

    @property
    def is_injection(self) -> bool:
        return self.score >= 0.5


def score_text(text: str) -> InjectionResult:
    """Score text for prompt-injection risk. Combines rule weights as
    independent evidence: 1 - prod(1 - w)."""
    views = [normalise(text)] + [normalise(p) for p in _decoded_payloads(text)]
    matched: dict[str, Rule] = {}
    for view in views:
        for rule in RULES:
            if rule.rule_id not in matched and rule.pattern.search(view):
                matched[rule.rule_id] = rule

    remaining = 1.0
    for rule in matched.values():
        remaining *= 1.0 - rule.weight
    score = round(1.0 - remaining, 3)
    return InjectionResult(
        score=score,
        matched=sorted(matched),
        families=sorted({r.family for r in matched.values()}),
    )
