"""Generate a deterministic day of raw auth-log events (JSON lines), including
the messiness real logs have: duplicates, nulls, bad timestamps, mixed case."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

USERS = [f"user{i:03d}" for i in range(60)]
GOOD_IPS = [f"10.0.{i}.{j}" for i in range(3) for j in range(1, 20)]
BAD_IPS = ["203.0.113.7", "198.51.100.23", "192.0.2.99"]


def generate_day(day: str, n: int = 3000, seed: int = 7) -> list[dict]:
    rng = random.Random(f"{seed}-{day}")  # noqa: S311 - synthetic test data, not crypto
    start = datetime.fromisoformat(day).replace(tzinfo=timezone.utc)
    events: list[dict] = []
    for i in range(n):
        attacker = rng.random() < 0.12
        ts = start + timedelta(seconds=rng.randint(0, 86_399))
        events.append(
            {
                "event_id": f"{day}-{i:06d}",
                "ts": ts.isoformat(),
                "user": rng.choice(USERS),
                "src_ip": rng.choice(BAD_IPS) if attacker else rng.choice(GOOD_IPS),
                "outcome": ("FAILURE" if attacker and rng.random() < 0.9 else
                            rng.choice(["SUCCESS"] * 9 + ["failure"])),
                "mfa": rng.random() < 0.7,
                "user_agent": rng.choice(["Mozilla/5.0", "curl/8.4.0", "python-requests/2.32", None]),
            }
        )
    # Messiness: 2% duplicates (at-least-once delivery), a few bad rows.
    events += [dict(e) for e in rng.sample(events, k=n // 50)]
    events.append({"event_id": f"{day}-bad1", "ts": "not-a-timestamp", "user": "user001",
                   "src_ip": "10.0.0.1", "outcome": "SUCCESS", "mfa": True, "user_agent": None})
    events.append({"event_id": f"{day}-bad2", "ts": start.isoformat(), "user": None,
                   "src_ip": "10.0.0.1", "outcome": "SUCCESS", "mfa": True, "user_agent": None})
    rng.shuffle(events)
    return events


def write_day(day: str, out_dir: Path, n: int = 3000) -> Path:
    path = out_dir / "bronze" / f"dt={day}" / "auth_events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(e) for e in generate_day(day, n)) + "\n")
    return path
