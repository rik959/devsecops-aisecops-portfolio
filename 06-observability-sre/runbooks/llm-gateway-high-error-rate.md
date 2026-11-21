# Runbook: LLMGatewayErrorBudgetFastBurn / SlowBurn

**Severity:** page · **Owner:** platform-security · **SLO:** 99.5% non-5xx on `/v1/chat` over 28 days

## 1. Confirm and scope (≤ 5 min)

```bash
kubectl -n ai-gateway get pods -l app.kubernetes.io/name=llm-gateway -o wide
kubectl -n ai-gateway rollout history deploy/llm-gateway
```

- Is the error ratio high on **all pods** or one? One pod points to a node problem: cordon the node and delete the pod.
- Did a **deploy** happen in the last hour? Check the Argo CD history. If yes, go straight to step 2.
- Is the upstream LLM provider degraded? Check its status page, and logs for `httpx.HTTPStatusError` / timeouts.

## 2. Mitigate first

| Cause | Action |
| --- | --- |
| Bad deploy | `argocd app rollback llm-gateway` (or `git revert` the commit: GitOps re-syncs) |
| Upstream provider outage | Switch `UPSTREAM_URL` to the secondary provider / region; communicate degraded mode |
| Saturation (CPU throttling, OOMKilled) | `kubectl -n ai-gateway scale deploy/llm-gateway --replicas=10`; check HPA max |
| Single bad node | `kubectl cordon <node>` then delete the affected pods |

## 3. Communicate

Post in `#inc-llm-gateway` every 30 minutes: impact, current mitigation, next update time.
Update the status page if customers are affected for more than 10 minutes.

## 4. After recovery

- Confirm the burn rate is back below 1× for 30 minutes.
- Open a postmortem from `../postmortem-template.md` within 2 business days.
- Record how much error budget the incident consumed.
