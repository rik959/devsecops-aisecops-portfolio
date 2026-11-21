"""Medallion pipeline (bronze -> silver -> gold) on DuckDB + Parquet.

    python -m pipeline.run --dt 2026-11-20 --data-dir data/

Properties an interviewer will probe:
  * Idempotent: each run overwrites exactly one dt= partition, so re-runs and
    backfills never duplicate data.
  * Quality gates between layers: the run fails (and gold is not published)
    if silver breaks its contract.
  * SQL lives in versioned .sql files; Python only orchestrates.
"""

from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import duckdb

SQL_DIR = Path(__file__).resolve().parents[1] / "sql"


def _sql(name: str, **params: str) -> str:
    return (SQL_DIR / f"{name}.sql").read_text().format(**params)


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str


def quality_checks(con: duckdb.DuckDBPyConnection, bronze_rows: int) -> list[CheckResult]:
    q = lambda s: con.execute(s).fetchone()[0]  # noqa: E731
    silver_rows = q("SELECT count(*) FROM silver")
    dupes = q("SELECT count(*) - count(DISTINCT event_id) FROM silver")
    null_keys = q("SELECT count(*) FROM silver WHERE user_id IS NULL OR event_ts IS NULL")
    bad_outcome = q("SELECT count(*) FROM silver WHERE outcome NOT IN ('SUCCESS','FAILURE')")
    kept = silver_rows / bronze_rows if bronze_rows else 0
    return [
        CheckResult("not_empty", silver_rows > 0, f"{silver_rows} rows"),
        CheckResult("unique_event_id", dupes == 0, f"{dupes} duplicates"),
        CheckResult("no_null_keys", null_keys == 0, f"{null_keys} null keys"),
        CheckResult("accepted_outcomes", bad_outcome == 0, f"{bad_outcome} bad outcomes"),
        # Guard against silent upstream breakage: dropping >10% of rows is a failure.
        CheckResult("row_retention_>=90%", kept >= 0.9, f"kept {kept:.1%} of bronze"),
    ]


def _write_partition(con: duckdb.DuckDBPyConnection, table: str, out_root: Path, dt: str) -> Path:
    part = out_root / table / f"dt={dt}"
    if part.exists():
        shutil.rmtree(part)  # overwrite-partition semantics -> idempotent
    part.mkdir(parents=True)
    path = part / "data.parquet"
    # table is one of three internal names; path is built from a validated dt.
    con.execute(f"COPY (SELECT * FROM {table}) TO '{path}' (FORMAT parquet, COMPRESSION zstd)")  # noqa: S608
    return path


def run(dt: str, data_dir: Path) -> dict:
    # dt is interpolated into SQL and paths, so accept only a strict ISO date.
    dt = date.fromisoformat(dt).isoformat()
    bronze = data_dir / "bronze" / f"dt={dt}" / "auth_events.jsonl"
    if not bronze.exists():
        raise FileNotFoundError(bronze)
    con = duckdb.connect()
    # Partition by UTC day regardless of where the job runs (a real bug caught in testing:
    # the host's local TZ shifted late-evening UTC events into the next day's partition).
    con.execute("SET TimeZone = 'UTC'")
    bronze_rows = con.execute(
        f"SELECT count(*) FROM read_json_auto('{bronze}', format='newline_delimited', union_by_name=true)"  # noqa: S608
    ).fetchone()[0]

    con.execute("CREATE TABLE silver AS " + _sql("silver_auth_events", bronze_path=str(bronze), dt=dt))
    checks = quality_checks(con, bronze_rows)
    if not all(c.passed for c in checks):
        failed = [f"{c.name}: {c.detail}" for c in checks if not c.passed]
        raise RuntimeError("silver quality checks failed: " + "; ".join(failed))

    con.execute("CREATE TABLE gold_ip_threat_daily AS " + _sql("gold_ip_threat_daily"))
    con.execute("CREATE TABLE gold_user_daily AS " + _sql("gold_user_daily"))

    outputs = {t: str(_write_partition(con, t, data_dir, dt))
               for t in ("silver", "gold_ip_threat_daily", "gold_user_daily")}
    spray = con.execute(
        "SELECT src_ip, distinct_users, failure_ratio FROM gold_ip_threat_daily WHERE suspected_spray"
    ).fetchall()
    return {
        "dt": dt,
        "bronze_rows": bronze_rows,
        "silver_rows": con.execute("SELECT count(*) FROM silver").fetchone()[0],
        "checks": {c.name: c.passed for c in checks},
        "suspected_spray_ips": [r[0] for r in spray],
        "outputs": outputs,
    }


def main(argv: list[str] | None = None) -> int:
    from .generate import write_day

    ap = argparse.ArgumentParser()
    ap.add_argument("--dt", required=True)
    ap.add_argument("--data-dir", type=Path, default=Path("data"))
    ap.add_argument("--generate", action="store_true", help="create synthetic bronze data first")
    args = ap.parse_args(argv)
    if args.generate:
        write_day(args.dt, args.data_dir)
    print(json.dumps(run(args.dt, args.data_dir), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
