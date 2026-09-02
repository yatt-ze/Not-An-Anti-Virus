#!/usr/bin/env python3
"""Summarize a CSV expense report into per-category totals.

Reads a CSV path from argv, writes a text summary to stdout. No network
access, no subprocess calls — a typical ad-hoc personal utility script.
"""
import csv
import sys
from collections import defaultdict


def main(path):
    totals = defaultdict(float)
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            totals[row["category"]] += float(row["amount"])
    for category, total in sorted(totals.items()):
        print(f"{category}: {total:.2f}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "expenses.csv")
