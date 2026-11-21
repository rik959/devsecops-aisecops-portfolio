# Secure AI Platform: DevSecOps · AISecOps · MLOps · Platform Engineering

[![python-ci](https://github.com/rik959/devsecops-aisecops-portfolio/actions/workflows/python-ci.yml/badge.svg)](https://github.com/rik959/devsecops-aisecops-portfolio/actions/workflows/python-ci.yml)
[![security](https://github.com/rik959/devsecops-aisecops-portfolio/actions/workflows/security.yml/badge.svg)](https://github.com/rik959/devsecops-aisecops-portfolio/actions/workflows/security.yml)
[![supply-chain](https://github.com/rik959/devsecops-aisecops-portfolio/actions/workflows/supply-chain.yml/badge.svg)](https://github.com/rik959/devsecops-aisecops-portfolio/actions/workflows/supply-chain.yml)
[![terraform](https://github.com/rik959/devsecops-aisecops-portfolio/actions/workflows/terraform.yml/badge.svg)](https://github.com/rik959/devsecops-aisecops-portfolio/actions/workflows/terraform.yml)

A reference platform for **running AI workloads securely on Kubernetes**:
from Terraform-provisioned AWS infrastructure, through a signed and scanned
software supply chain and admission control, to an LLM security gateway, an
MLOps pipeline, a security data pipeline and SLO-based operations.

The projects build on each other, and each one also stands alone with its own README and tests.

```
 ┌──────────────────────────── GitHub Actions ─────────────────────────────┐
 │ lint/test · Semgrep · gitleaks · Trivy · Checkov · eval & model gates    │
 │ build ─► scan ─► SBOM ─► push ─► cosign sign ─► SLSA provenance          │
 └───────────────┬──────────────────────────────────────────┬──────────────┘
                 │ OIDC (no stored keys)                    │ signed image
                 ▼                                          ▼
   01 Terraform: VPC + hardened EKS + ECR     02 Kyverno verifies signature + SBOM at admission
                 │                                          │
                 └──────────────► EKS cluster ◄─────────────┘
                                      │
       ┌──────────────────────────────┼───────────────────────────────┐
       ▼                              ▼                               ▼
 03 LLM Security Gateway      04 Login-risk model (MLOps)      05 Auth-log pipeline
 injection · PII · output     validate · drift · gate · serve  bronze ─► silver ─► gold
       │                              │                               │
       └──────── metrics ─────► 06 SLOs, burn-rate alerts, detections, runbooks
                                      ▲
            07 Vulnerability triage: Trivy reports ─► ranked backlog + SLAs + CI gate
```

## Projects

| # | Project | Role it demonstrates | Highlights |
| --- | --- | --- | --- |
| 01 | [Terraform: hardened AWS EKS](01-terraform-aws-eks/) | Platform / Cloud / DevOps | KMS-encrypted secrets, private API, IMDSv2 hop-limit 1, Bottlerocket, access entries, GitHub OIDC, flow logs. **Checkov: 192 passed, 0 failed** |
| 02 | [Kubernetes platform security](02-k8s-platform-security/) | DevSecOps / Platform Security | Kyverno: pod hardening, **cosign signature + SBOM verification**, auto default-deny; PSS restricted; NetworkPolicies blocking IMDS; least-privilege RBAC; hardened Helm chart; Argo CD |
| 03 | [LLM Security Gateway](03-llm-security-gateway/) | **AISecOps / AI Security** | OWASP LLM Top 10 controls: prompt-injection scoring, PII/secret redaction, exfiltration-safe output handling, rate limiting, audit log; eval gate in CI |
| 04 | [MLOps pipeline](04-mlops-pipeline/) | MLOps / ML Platform | Data validation, PSI drift detection, PR-AUC quality gate, model card, checksum-verified model loading, Airflow DAG, MLflow hook |
| 05 | [Security data pipeline](05-data-pipeline/) | Data Engineering | DuckDB medallion over auth logs, idempotent partitions, quality gates, UTC-safe partitioning, password-spray detection |
| 06 | [Observability & SRE](06-observability-sre/) | SRE | 99.5% SLO, multi-window burn-rate alerts, security detections (MITRE ATLAS), Grafana dashboard, runbooks, postmortem template |
| 07 | [Vulnerability management](07-vuln-management-automation/) | DevSecOps / Vuln Mgmt | Trivy report dedupe across images, contextual risk scoring (KEV, exposure, fixability), SLA due dates, CI gate |

## CI/CD and DevSecOps pipeline

| Workflow | What runs | Gate |
| --- | --- | --- |
| `python-ci` | ruff (incl. bandit-style `S` rules) + pytest for 4 projects; injection eval; model training | Fails on lint, tests, precision/recall < 0.9, PR-AUC < 0.5 |
| `security` | gitleaks, Semgrep SAST (reported to the Security tab), Trivy fs (dependency CVEs, secrets), dependency review, OpenSSF Scorecard | Fails on secrets, fixable HIGH/CRITICAL CVEs, risky new dependencies |
| `supply-chain` | Build → Trivy image scan → CycloneDX SBOM → push to GHCR → cosign keyless sign → SBOM attestation → SLSA provenance → verify | Fails on fixable HIGH/CRITICAL in the image |
| `terraform` | fmt, validate, tflint, Checkov (SARIF to the Security tab); OIDC plan on main | Fails on any Checkov finding |
| `kubernetes` | helm lint, kubeconform, Checkov, promtool, Kyverno CLI (bad pod must be rejected) | Fails if policies don't block a privileged `:latest` pod |

Every workflow uses least-privilege `permissions:`, `persist-credentials: false`,
and OIDC instead of long-lived cloud keys. Dependabot keeps actions, pip,
Docker and Terraform dependencies current.

## Run everything locally

```bash
make test        # all Python tests (37) + eval and model gates
make lint        # ruff, terraform fmt, promtool
```

## How this was verified

- **Python:** 37 tests pass across the 4 Python projects; ruff clean.
- **Terraform:** `validate` passes (checked with OpenTofu 1.8 + AWS provider 5.80); Checkov 192/192 with 11 documented skips (`# checkov:skip=` with a reason on each).
- **Prometheus rules:** `promtool check rules` passes (15 rules).
- **Workflows:** `actionlint` clean.
- **Not yet run in a live cluster or AWS account:** the Helm chart, Kyverno policies and Docker images are validated in CI (helm lint, kubeconform, Kyverno CLI, image build), not against real infrastructure.

## About

Built by **Riktam Bera**, DevOps engineer at Ericsson working on DevSecOps and
AISecOps (vulnerability management, secure CI/CD supply chains, Keycloak
OIDC/IAM, LangGraph-based AI security platforms) and on large-scale
Kubernetes/OpenShift automation.
[LinkedIn](https://linkedin.com/in/riktam-bera) · [GitHub](https://github.com/rik959)

Licensed under the [MIT License](LICENSE).
