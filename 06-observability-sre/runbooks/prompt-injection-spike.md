# Runbook: PromptInjectionSpike

**Severity:** high · **Owner:** security on-call · **MITRE ATLAS:** AML.T0051 LLM Prompt Injection

The gateway is blocking injection attempts at more than 3× the trailing 24-hour rate.
The controls are working; the question is **who is probing, and did anything get through?**

## 1. Identify the source

The audit log holds hashes and scores, never raw prompts:

```bash
kubectl -n ai-gateway logs -l app.kubernetes.io/name=llm-gateway --since=30m \
  | jq -r 'select(.event=="prompt_evaluated" and .decision=="block") | [.who, (.families|join(","))] | @tsv' \
  | sort | uniq -c | sort -rn | head
```

- **One API key / IP dominating:** a targeted probe. Go to step 2.
- **Many identities, same attack family:** a public jailbreak is circulating. Go to step 3.

## 2. Contain a single actor

- Revoke or rotate that API key (remove its hash from `API_KEY_SHA256`), or block the IP at the WAF.
- Check for **near-misses**: prompts from the same identity that were *allowed* with `injection_score` between 0.3 and 0.5.

## 3. Harden against a new technique

- Add the new pattern to `03-llm-security-gateway/evals/cases.jsonl` as an `attack` case.
- Add or adjust a rule in `app/guards/injection.py`; CI's eval gate prevents regressions on benign prompts.
- Consider temporarily lowering `INJECTION_THRESHOLD` to 0.4 (expect more false positives).

## 4. Check for impact

- Did any allowed response for that identity include `output_actions` like `removed_external_image` or `redacted:*`? Those indicate an exfiltration attempt that reached the model.
- If tools or agents are connected downstream, review their action logs for the same time window.
