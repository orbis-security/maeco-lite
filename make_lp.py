#!/usr/bin/env python3
"""Convert examples JSON to DL-Learner lp.* assignment format (5-fold cross-validation)."""

import json
import sys
from pathlib import Path


def make_folds(items: list[str], n_folds: int = 5) -> list[list[str]]:
    """Split items into n_folds roughly equal folds."""
    folds = []
    size = len(items)
    for i in range(n_folds):
        start = i * size // n_folds
        end = (i + 1) * size // n_folds
        folds.append(items[start:end])
    return folds


def format_set(hashes: list[str]) -> str:
    values = ",\n  ".join(f'"ex:{h}"' for h in hashes)
    return "{\n  " + values + "\n}"


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <examples.json>", file=sys.stderr)
        return 1

    with open(sys.argv[1]) as f:
        data = json.load(f)

    pos = data.get("positive_examples", [])
    neg = data.get("negative_examples", [])

    n_folds = 5
    pos_folds = make_folds(pos, n_folds)
    neg_folds = make_folds(neg, n_folds)

    out_dir = Path(sys.argv[1]).parent

    for i in range(n_folds):
        pos_test = pos_folds[i]
        pos_train = [ex for j, fold in enumerate(pos_folds) if j != i for ex in fold]
        neg_test = neg_folds[i]
        neg_train = [ex for j, fold in enumerate(neg_folds) if j != i for ex in fold]

        out_path = out_dir / f"fold_{i + 1}.lp"
        with open(out_path, "w") as f:
            f.write(f"lp.positiveExamples = {format_set(pos_train)}\n")
            f.write(f"lp.negativeExamples = {format_set(neg_train)}\n")
            f.write(f"lp.positiveTestExamples = {format_set(pos_test)}\n")
            f.write(f"lp.negativeTestExamples = {format_set(neg_test)}\n")

        print(f"Wrote {out_path} ({len(pos_train)} pos train, {len(neg_train)} neg train, "
              f"{len(pos_test)} pos test, {len(neg_test)} neg test)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
