# 01 · Terraform: Hardened AWS EKS Platform

Reusable Terraform modules for a security-first EKS platform, plus a `dev`
environment that wires them together with ECR and GitHub OIDC.

```
                     ┌──────────────── VPC 10.20.0.0/16 (3 AZs) ────────────────┐
  Internet ─► IGW ─► │ public /24 ×3   (ALB/NLB, NAT GW)                       │
                     │ private /20 ×3  (Bottlerocket nodes, IMDSv2, hop limit 1)│ ─► S3 gateway endpoint
                     │ intra /24 ×3    (EKS control-plane ENIs, no internet)   │
                     └──────────── VPC flow logs ─► CloudWatch (KMS) ──────────┘
  GitHub Actions ──OIDC──► IAM role (main branch only) ──► ECR (immutable, scan-on-push, KMS)
```

## Security controls

| Control | Why it matters | Where |
| --- | --- | --- |
| K8s Secrets envelope-encrypted with a customer-managed KMS key (rotation on) | Secrets in etcd are only base64-encoded by default | `modules/eks` |
| Private API endpoint; public access only from allow-listed CIDRs, `0.0.0.0/0` rejected by validation | Shrinks the attack surface of the control plane | `modules/eks/variables.tf` |
| All 5 control-plane log types, incl. `audit` | Needed for incident response and detection | `modules/eks` |
| EKS access entries, `API` auth mode, no creator auto-admin | Replaces the fragile `aws-auth` ConfigMap; explicit admins only | `modules/eks` |
| IMDSv2 required, hop limit 1 | Stops pods stealing node IAM credentials (SSRF → IMDS) | launch template |
| Bottlerocket nodes, encrypted gp3, SSM instead of SSH | Minimal immutable OS, no SSH keys to leak | node group |
| IRSA OIDC provider + Pod Identity agent | Per-workload IAM instead of a shared node role | `modules/eks` |
| Default security group locked down, VPC flow logs (KMS) | CIS AWS benchmark items, forensics | `modules/vpc` |
| GitHub OIDC, `sub` pinned to `repo:…:ref:refs/heads/main` | No long-lived AWS keys in CI; forks/PR branches can't assume the role | `environments/dev` |
| ECR immutable tags, scan on push, lifecycle policy | Tags can't be overwritten after the scan | `environments/dev` |
| S3 backend with native lockfile (TF ≥ 1.10), encryption | Shared state, no concurrent applies, no DynamoDB table | `versions.tf` |

## Usage

```bash
cd environments/dev
cp terraform.tfvars.example terraform.tfvars        # set your IP + admin role
# edit the backend bucket name in versions.tf
terraform init && terraform plan -out tfplan
terraform apply tfplan
$(terraform output -raw kubeconfig_command)
```

CI runs `terraform fmt -check`, `terraform validate`, `tflint` and **Checkov**
on every PR (see `.github/workflows/terraform.yml`).

## Cost notes (dev)

A single NAT gateway and Spot nodes keep dev cheap. The EKS control plane
(~$73/month) plus 2 × m6i.large Spot nodes comes to roughly $120–150/month in
eu-central-1. Run `terraform destroy` when you're not using it. Prod should use
one NAT gateway per AZ and on-demand nodes, or Karpenter with a Spot/on-demand mix.
