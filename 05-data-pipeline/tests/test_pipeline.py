import json
import sys
from pathlib import Path

import duckdb
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.generate import write_day  # noqa: E402
from pipeline.run import run  # noqa: E402

DT = "2026-11-20"


@pytest.fixture()
def data_dir(tmp_path):
    write_day(DT, tmp_path, n=2000)
    return tmp_path


def test_pipeline_cleans_and_dedupes(data_dir):
    result = run(DT, data_dir)
    assert result["bronze_rows"] == 2000 + 40 + 2
    assert result["silver_rows"] == 2000  # duplicates and 2 bad rows removed
    assert all(result["checks"].values())


def test_detects_password_spray_ips(data_dir):
    result = run(DT, data_dir)
    assert set(result["suspected_spray_ips"]) == {"203.0.113.7", "198.51.100.23", "192.0.2.99"}


def test_rerun_is_idempotent(data_dir):
    first = run(DT, data_dir)
    second = run(DT, data_dir)
    silver = Path(second["outputs"]["silver"])
    assert len(list(silver.parent.glob("*.parquet"))) == 1
    count = duckdb.connect().execute(f"SELECT count(*) FROM '{silver}'").fetchone()[0]
    assert count == first["silver_rows"]


def test_quality_gate_blocks_bad_upstream(tmp_path):
    bronze = tmp_path / "bronze" / f"dt={DT}" / "auth_events.jsonl"
    bronze.parent.mkdir(parents=True)
    rows = [{"event_id": str(i), "ts": "garbage", "user": "u", "src_ip": "1.1.1.1",
             "outcome": "SUCCESS", "mfa": True, "user_agent": None} for i in range(50)]
    rows += [{"event_id": "ok", "ts": f"{DT}T10:00:00+00:00", "user": "u", "src_ip": "1.1.1.1",
              "outcome": "SUCCESS", "mfa": True, "user_agent": None}]
    bronze.write_text("\n".join(json.dumps(r) for r in rows))
    with pytest.raises(RuntimeError, match="row_retention"):
        run(DT, tmp_path)
    assert not (tmp_path / "gold_ip_threat_daily").exists()
