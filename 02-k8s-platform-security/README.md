# 02 · Kubernetes Platform Security

Admission policies, network isolation, RBAC and a hardened Helm chart.
Together they make the secure configuration the default, and an insecure
one impossible to deploy.

| Layer | Control | File |
| --- | --- | --- |
| Admission (Kyverno) | No privileged / root / host namespaces / hostPath; read-only root FS; drop ALL capabilities; RuntimeDefault seccomp | `kyverno/pod-security.yaml` |
| Supply chain | Only `ghcr.io/rik959/*` or platform ECR; no `:latest`; **cosign keyless signature + CycloneDX SBOM attestation verified at admission**, tag rewritten to digest | `kyverno/supply-chain.yaml` |
| Reliability guardrails | Requests + memory limit required, readiness probe required, owner label required | `kyverno/resources-and-labels.yaml` |
| Secure-by-default namespaces | Kyverno *generates* a default-deny NetworkPolicy in every new namespace | `kyverno/resources-and-labels.yaml` |
| Pod Security Standards | Namespace labelled `enforce: restricted`, a second, built-in layer independent of Kyverno | `network-policies/ai-gateway.yaml` |
| Network | Default deny; DNS allowed; gateway ingress only from ingress-nginx and monitoring; egress only on 443 to public IPs, **instance metadata 169.254.169.254 blocked** | `network-policies/ai-gateway.yaml` |
| RBAC | Developers get read-only access: no Secrets, no `exec`, no port-forward | `rbac/developer-readonly.yaml` |
| Workload | Non-root UID 65532, no SA token mounted, upstream API key mounted as a 0400 file (not env), optional digest pinning, PDB, zone spread, HPA, preStop drain, `/tmp` as a size-limited emptyDir | `helm/llm-gateway/` |
| GitOps | Argo CD app with self-heal; AppProject forbids cluster-scoped resources | `argocd/` |

## Apply (on the EKS cluster from project 01)

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/ && helm install kyverno kyverno/kyverno -n kyverno --create-namespace
kubectl apply -f kyverno/ -f network-policies/ -f rbac/
kubectl apply -f argocd/llm-gateway-app.yaml       # Argo CD deploys the chart
```

Try to break it:

```bash
kubectl -n ai-gateway run bad --image=nginx:latest --privileged
# -> admission webhook "validate.kyverno.svc" denied the request: trusted-registries-no-latest ...
```

CI renders the chart and checks it with `helm lint`, **kubeconform**
(schema) and **Checkov** (misconfigurations). See `.github/workflows/kubernetes.yml`.

## Rollout advice

In an existing cluster, start every policy with `validationFailureAction: Audit`.
Review the PolicyReports for a week, fix the violators, then switch to `Enforce`
one policy at a time.
