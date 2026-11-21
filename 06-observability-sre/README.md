# 06 · Observability & SRE

SLOs, alerting, dashboards and incident process for the LLM Security Gateway
(project 03). Every alert links to a runbook, and every security signal maps
to a detection.

| File | What it is |
| --- | --- |
| `prometheus/slo-rules.yaml` | 99.5% availability SLO: recording rules + **multi-window, multi-burn-rate** alerts (14.4×/1h, 6×/6h page; 1×/3d ticket) and a p99 latency alert |
| `prometheus/security-alerts.yaml` | Detections: prompt-injection spike vs 24h baseline (MITRE ATLAS AML.T0051), PII-redaction surge, rate-limit abuse, Kyverno violations, namespaces without PSS `restricted` |
| `grafana/llm-gateway-dashboard.json` | Availability, error budget remaining, burn rate, latency, security events |
| `runbooks/` | Step-by-step response for the error-budget and prompt-injection alerts |
| `postmortem-template.md` | Blameless postmortem with impact, timeline, 5 whys, action items |

The metrics come straight from the gateway (`prometheus_client`):
`http_requests_total{handler,method,status}`, `http_request_duration_seconds`,
`llm_gateway_blocked_injection_total`, `llm_gateway_pii_redactions_total{entity}`
and others.

## Why multi-window burn rate?

A plain "error rate > 1% for 5 minutes" alert pages on harmless blips and
misses slow leaks. Burn-rate alerts page in proportion to how fast the
**error budget** is disappearing. The short second window (5m, 30m) lets the
alert clear quickly once the problem is fixed.

| Alert | Burn rate | Windows | Budget consumed when it fires |
| --- | --- | --- | --- |
| Fast burn (page) | 14.4× | 1h and 5m | 2% |
| Slow burn (page) | 6× | 6h and 30m | 5% |
| At risk (ticket) | 1× | 3d and 6h | on track to exhaust it |

```bash
promtool check rules prometheus/*.yaml    # run in CI
```
