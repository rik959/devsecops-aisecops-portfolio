"""CLI: triage Trivy reports into a ranked backlog and act as a CI gate.

    python -m vulnmgmt.cli sample-reports/*.json \
        --kev kev.txt --internet-facing ghcr.io/acme/api:1.4.2 \
        --format markdown --fail-on HIGH
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .core import gate, load_reports, to_markdown, triage


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vulnmgmt")
    ap.add_argument("reports", nargs="+", type=Path, help="Trivy JSON reports")
    ap.add_argument("--kev", type=Path, help="file with one known-exploited CVE id per line")
    ap.add_argument("--internet-facing", action="append", default=[], help="asset name (repeatable)")
    ap.add_argument("--format", choices=["markdown", "json", "csv"], default="markdown")
    ap.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None)
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args(argv)

    kev = set()
    if args.kev:
        kev = {ln.strip() for ln in args.kev.read_text().splitlines() if ln.strip() and not ln.startswith("#")}

    triaged = triage(load_reports(args.reports), kev=kev, internet_facing_assets=set(args.internet_facing))

    if args.format == "markdown":
        sys.stdout.write(to_markdown(triaged, top=args.top))
    elif args.format == "json":
        json.dump([asdict(t) for t in triaged], sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        rows = [asdict(t) for t in triaged]
        if rows:
            w = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]))
            w.writeheader()
            for r in rows:
                r["assets"] = ";".join(r["assets"])
                w.writerow(r)

    if args.fail_on and gate(triaged, args.fail_on):
        print(f"\nGATE FAILED: fixable findings at or above {args.fail_on}, or known-exploited CVEs present.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
