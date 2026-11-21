"""Vulnerability triage engine.

Takes raw scanner output (Trivy JSON today; the `Finding` model is
scanner-agnostic), de-duplicates across images, scores risk with context, and
assigns remediation SLAs. This is the automation layer of a vulnerability
management programme: scanners produce noise, this turns it into a ranked
backlog with due dates.

Risk score (0-100) =
    severity base (CRITICAL 40 / HIGH 30 / MEDIUM 15 / LOW 5)
  + 25 if the CVE is in the known-exploited list (CISA KEV style)
  + 15 if the asset is internet-facing
  + 10 if a fixed version exists (cheap to fix -> do it now)
  + up to 10 from CVSS (cvss * 1)
capped at 100.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Iterable

SEVERITY_BASE = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 15, "LOW": 5, "UNKNOWN": 5}
SLA_DAYS = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180, "UNKNOWN": 180}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


@dataclass
class Finding:
    cve: str
    package: str
    installed: str
    fixed: str | None
    severity: str
    cvss: float
    title: str
    assets: set[str] = field(default_factory=set)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.cve, self.package, self.installed)


@dataclass
class TriagedFinding:
    cve: str
    package: str
    installed: str
    fixed: str | None
    severity: str
    cvss: float
    title: str
    assets: list[str]
    known_exploited: bool
    internet_facing: bool
    risk_score: int
    due_date: str


def _best_cvss(vuln: dict) -> float:
    scores = []
    for source in (vuln.get("CVSS") or {}).values():
        for k in ("V3Score", "V2Score"):
            if isinstance(source.get(k), (int, float)):
                scores.append(float(source[k]))
    return max(scores, default=0.0)


def parse_trivy(report: dict) -> list[Finding]:
    asset = report.get("ArtifactName", "unknown")
    out: list[Finding] = []
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            out.append(
                Finding(
                    cve=v["VulnerabilityID"],
                    package=v.get("PkgName", "?"),
                    installed=v.get("InstalledVersion", "?"),
                    fixed=v.get("FixedVersion") or None,
                    severity=(v.get("Severity") or "UNKNOWN").upper(),
                    cvss=_best_cvss(v),
                    title=(v.get("Title") or "")[:160],
                    assets={asset},
                )
            )
    return out


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    merged: dict[tuple[str, str, str], Finding] = {}
    for f in findings:
        if f.key in merged:
            merged[f.key].assets |= f.assets
        else:
            merged[f.key] = Finding(**{**asdict(f), "assets": set(f.assets)})
    return list(merged.values())


def score(f: Finding, kev: set[str], internet_facing_assets: set[str]) -> int:
    s = SEVERITY_BASE.get(f.severity, 5)
    if f.cve in kev:
        s += 25
    if f.assets & internet_facing_assets:
        s += 15
    if f.fixed:
        s += 10
    s += min(10, round(f.cvss))
    return min(100, s)


def triage(
    findings: Iterable[Finding],
    kev: set[str] | None = None,
    internet_facing_assets: set[str] | None = None,
    today: date | None = None,
) -> list[TriagedFinding]:
    kev = kev or set()
    internet = internet_facing_assets or set()
    today = today or date.today()
    out = []
    for f in dedupe(findings):
        known = f.cve in kev
        sla = SLA_DAYS.get(f.severity, 180)
        if known:  # actively exploited: treat as an emergency regardless of label
            sla = min(sla, 3)
        out.append(
            TriagedFinding(
                cve=f.cve,
                package=f.package,
                installed=f.installed,
                fixed=f.fixed,
                severity=f.severity,
                cvss=f.cvss,
                title=f.title,
                assets=sorted(f.assets),
                known_exploited=known,
                internet_facing=bool(f.assets & internet),
                risk_score=score(f, kev, internet),
                due_date=(today + timedelta(days=sla)).isoformat(),
            )
        )
    out.sort(key=lambda t: (-t.risk_score, SEVERITY_ORDER.index(t.severity), t.cve))
    return out


def load_reports(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for p in paths:
        findings.extend(parse_trivy(json.loads(Path(p).read_text())))
    return findings


def summary(triaged: list[TriagedFinding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for t in triaged:
        counts[t.severity] = counts.get(t.severity, 0) + 1
    counts["fixable"] = sum(1 for t in triaged if t.fixed)
    counts["known_exploited"] = sum(1 for t in triaged if t.known_exploited)
    return counts


def gate(triaged: list[TriagedFinding], fail_on: str) -> bool:
    """True if the build should FAIL: any fixable finding at or above `fail_on`,
    or any known-exploited finding."""
    limit = SEVERITY_ORDER.index(fail_on.upper())
    return any(
        t.known_exploited or (t.fixed and SEVERITY_ORDER.index(t.severity) <= limit)
        for t in triaged
    )


def to_markdown(triaged: list[TriagedFinding], top: int = 25) -> str:
    s = summary(triaged)
    lines = [
        "## Vulnerability triage report",
        "",
        f"**{len(triaged)} unique findings** · "
        + " · ".join(f"{k.title()}: {s[k]}" for k in SEVERITY_ORDER if s[k])
        + f" · Fixable: {s['fixable']} · Known exploited: {s['known_exploited']}",
        "",
        "| Risk | Severity | CVE | Package | Installed → Fixed | Assets | Due |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for t in triaged[:top]:
        flag = " 🔥" if t.known_exploited else ""
        lines.append(
            f"| {t.risk_score} | {t.severity}{flag} | {t.cve} | {t.package} | "
            f"{t.installed} → {t.fixed or 'no fix'} | {len(t.assets)} | {t.due_date} |"
        )
    return "\n".join(lines) + "\n"
