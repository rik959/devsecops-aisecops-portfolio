# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use
[GitHub private vulnerability reporting](https://github.com/rik959/devsecops-aisecops-portfolio/security/advisories/new)
instead. I aim to acknowledge reports within 3 business days.

## Scope

This is a reference/portfolio repository. The LLM gateway's rule-based
injection detector is a demonstration layer, not a complete defence. See the
limitations section in `03-llm-security-gateway/README.md` before using it in production.

## Supply chain

Release images (`ghcr.io/rik959/llm-security-gateway`) are signed with
Sigstore cosign (keyless) and carry a CycloneDX SBOM and SLSA provenance. Verify with:

```bash
cosign verify ghcr.io/rik959/llm-security-gateway@<digest> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/rik959/devsecops-aisecops-portfolio/.github/workflows/supply-chain.yml@refs/heads/main
```
