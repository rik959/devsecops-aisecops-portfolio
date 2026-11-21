"""Output handling (OWASP LLM05: improper output handling).

Model output is untrusted. Before it reaches a browser, a tool, or a shell:
  * strip markdown images pointing at external hosts (zero-click exfiltration),
  * drop links to domains outside an allow-list,
  * redact secrets / PII the model may have echoed,
  * flag (not execute) shell-looking content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .pii import redact

MD_IMAGE = re.compile(r"!\[([^\]]*)\]\((\S+?)\)")
MD_LINK = re.compile(r"(?<!!)\[([^\]]+)\]\((\S+?)\)")
DANGEROUS_SHELL = re.compile(r"(rm\s+-rf\s+/|curl\s+[^|]+\|\s*(ba)?sh|mkfs\.|:\(\)\s*\{\s*:\|:&\s*\};:)")


@dataclass
class OutputResult:
    text: str
    actions: list[str] = field(default_factory=list)


def _host_allowed(url: str, allowed: set[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in allowed)


def sanitise_output(text: str, allowed_domains: set[str]) -> OutputResult:
    actions: list[str] = []

    def _img(m: re.Match[str]) -> str:
        if _host_allowed(m.group(2), allowed_domains):
            return m.group(0)
        actions.append("removed_external_image")
        return f"[image removed: {m.group(1) or 'untrusted source'}]"

    def _link(m: re.Match[str]) -> str:
        if _host_allowed(m.group(2), allowed_domains):
            return m.group(0)
        actions.append("defanged_link")
        return f"{m.group(1)} (link removed)"

    text = MD_IMAGE.sub(_img, text)
    text = MD_LINK.sub(_link, text)

    red = redact(text)
    if red.findings:
        actions.append("redacted:" + ",".join(sorted(red.findings)))
    text = red.text

    if DANGEROUS_SHELL.search(text):
        actions.append("flagged_dangerous_shell")
    return OutputResult(text=text, actions=actions)
