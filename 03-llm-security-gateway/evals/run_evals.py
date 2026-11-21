"""Offline eval for the injection detector. Prints precision/recall/F1 and
exits non-zero if they fall below thresholds, so CI fails on regressions.

    python evals/run_evals.py --min-recall 0.9 --min-precision 0.9
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.guards import score_text  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=str(Path(__file__).with_name("cases.jsonl")))
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--min-recall", type=float, default=0.9)
    ap.add_argument("--min-precision", type=float, default=0.9)
    args = ap.parse_args()

    tp = fp = fn = tn = 0
    misses = []
    for line in Path(args.cases).read_text().splitlines():
        if not line.strip():
            continue
        case = json.loads(line)
        predicted = score_text(case["prompt"]).score >= args.threshold
        actual = case["label"] == "attack"
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
            misses.append(("false_positive", case["id"]))
        elif actual:
            fn += 1
            misses.append(("false_negative", case["id"]))
        else:
            tn += 1

    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    print(json.dumps({"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                      "precision": round(precision, 3), "recall": round(recall, 3),
                      "f1": round(f1, 3), "misses": misses}, indent=2))
    ok = precision >= args.min_precision and recall >= args.min_recall
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
