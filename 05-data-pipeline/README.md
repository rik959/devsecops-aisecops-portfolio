# 05 · Data Pipeline: Security Auth-Log Medallion

A bronze → silver → gold pipeline over raw authentication logs, built on
**DuckDB + Parquet**. It produces SOC-ready tables and flags
**password-spray source IPs**.

```
bronze/dt=…/auth_events.jsonl      raw, messy (duplicates, nulls, bad timestamps, mixed case)
        │  sql/silver_auth_events.sql   type, normalise, dedupe (row_number), filter to UTC day
        ▼
silver/dt=…/data.parquet           ──► quality gate (5 checks) ── fail → nothing published
        │
        ├─ sql/gold_ip_threat_daily.sql   attempts, distinct users, failure ratio, suspected_spray
        └─ sql/gold_user_daily.sql        per-user logins, failures, successes without MFA
```

```bash
pip install duckdb pytest
python -m pipeline.run --dt 2026-11-20 --data-dir data --generate
pytest -q    # 4 tests
```

## What it demonstrates

| Concept | How |
| --- | --- |
| Idempotency | Each run overwrites exactly one `dt=` partition, so re-runs and backfills never duplicate. A test proves it. |
| Dedupe of at-least-once delivery | `row_number() OVER (PARTITION BY event_id)` |
| Data contracts / quality gates | Not empty, unique keys, no null keys, accepted values, ≥ 90% row retention (catches silent upstream breakage) |
| Timezone-safe partitioning | Session pinned to UTC; a test caught late-evening UTC events leaking into the next partition when the host was in IST |
| SQL-first transforms | Logic lives in versioned `.sql` files; Python only orchestrates (the same pattern dbt formalises) |
| Detection engineering | Spray heuristic: ≥ 10 distinct users and ≥ 50% failures from one IP in a day |

## Scaling it

The same layout maps directly onto Spark or Databricks with Delta/Iceberg tables,
partitioned by `dt`. Use `MERGE` for late-arriving events, Airflow for scheduling,
and Great Expectations or dbt tests in place of `quality_checks()`.
