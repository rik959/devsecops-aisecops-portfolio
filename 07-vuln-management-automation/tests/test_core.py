import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vulnmgmt.cli import main  # noqa: E402
from vulnmgmt.core import gate, load_reports, summary, triage  # noqa: E402

REPORTS = sorted((ROOT / "sample-reports").glob("*.json"))
KEV = {"CVE-2024-3094", "CVE-2023-44487", "CVE-2023-4911"}


def test_dedupe_merges_assets():
    t = triage(load_reports(REPORTS))
    rapid = [x for x in t if x.cve == "CVE-2023-44487"]
    assert len(rapid) == 1
    assert rapid[0].assets == ["ghcr.io/acme/api:1.4.2", "ghcr.io/acme/worker:2.0.1"]
    assert len(t) == 5  # 6 raw findings, 1 duplicate


def test_ranking_and_kev_sla():
    t = triage(load_reports(REPORTS), kev=KEV, internet_facing_assets={"ghcr.io/acme/api:1.4.2"},
               today=date(2026, 1, 1))
    assert t[0].cve == "CVE-2024-3094"
    assert t[0].risk_score == 100
    assert t[0].due_date == "2026-01-04"  # KEV -> 3 days
    low = next(x for x in t if x.severity == "LOW")
    assert low.due_date == "2026-06-30"  # 180 days


def test_summary_counts():
    s = summary(triage(load_reports(REPORTS), kev=KEV))
    assert s["CRITICAL"] == 1 and s["HIGH"] == 2 and s["MEDIUM"] == 1 and s["LOW"] == 1
    assert s["fixable"] == 4
    assert s["known_exploited"] == 3


def test_gate():
    t = triage(load_reports(REPORTS))
    assert gate(t, "HIGH")
    only_low = [x for x in t if x.severity == "LOW"]
    assert not gate(only_low, "HIGH")


def test_cli_markdown_and_gate(capsys):
    rc = main([*map(str, REPORTS), "--kev", str(ROOT / "sample-reports/kev.txt"), "--fail-on", "CRITICAL"])
    out = capsys.readouterr().out
    assert "Vulnerability triage report" in out
    assert rc == 1
