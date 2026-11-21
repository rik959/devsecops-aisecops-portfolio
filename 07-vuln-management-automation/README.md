# 07 · Vulnerability Management Automation

Scanners produce noise; a vulnerability-management programme needs a ranked
backlog with owners and due dates. This tool takes Trivy JSON reports from many
images, **de-duplicates** findings across them, **scores risk with context**
(known exploitation, internet exposure, fix availability, CVSS), assigns
**remediation SLAs**, and acts as a **CI gate**.

```bash
trivy image -f json -o api.json ghcr.io/acme/api:1.4.2      # one report per image

python -m vulnmgmt.cli sample-reports/*.json \
  --kev sample-reports/kev.txt \
  --internet-facing ghcr.io/acme/api:1.4.2 \
  --format markdown            # or json / csv
  --fail-on HIGH               # exit 1 if fixable HIGH+ or any known-exploited CVE
```

Sample output:

| Risk | Severity | CVE | Package | Installed → Fixed | Assets | Due |
| --- | --- | --- | --- | --- | --- | --- |
| 100 | CRITICAL 🔥 | CVE-2024-3094 | liblzma5 | 5.6.0-0.2 → 5.6.1+really5.4.5-1 | 1 | +3 days |
| 88 | HIGH 🔥 | CVE-2023-44487 | libnghttp2-14 | 1.52.0-1 → 1.52.0-1+deb12u1 | 2 | +3 days |
| 46 | MEDIUM | CVE-2024-35195 | requests | 2.31.0 → 2.32.0 | 1 | +90 days |

## Risk model

| Factor | Points |
| --- | --- |
| Severity base | Critical 40 · High 30 · Medium 15 · Low 5 |
| In known-exploited list (CISA KEV) | +25, and SLA shortened to 3 days |
| Asset is internet-facing | +15 |
| Fixed version available | +10 |
| CVSS score | +0–10 |

SLAs: Critical 7 d · High 30 d · Medium 90 d · Low 180 d.

## Why this design

- **Dedupe by (CVE, package, version):** one base-image bug in 40 services is one fix, not 40 tickets.
- **The gate only fails on fixable findings (plus KEV):** blocking builds on CVEs with no upstream fix trains teams to ignore the gate.
- **Scanner-agnostic `Finding` model:** add a parser for Grype, Snyk or Prisma without touching scoring.

Next steps you could add: pull the live CISA KEV feed and EPSS scores, open
Jira/GitHub issues per finding with an owner from `CODEOWNERS`, and track MTTR.

```bash
pytest -q   # 5 tests
```
