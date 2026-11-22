#!/usr/bin/env python3
"""Write multi-block bzip2 seeds that fit the nightly -max_len of 32768 (§11.9).

Usage: gen_bzip2_small.py <output-dir>
"""
import bz2
import os
import random
import sys

BLOCK = 100_000  # Level 1 block size, so a little over this spans two blocks.


def text(n, seed):
    rng = random.Random(seed)
    words = [bytes(rng.choices(b"abcdefgh", k=rng.randint(2, 7))) for _ in range(40)]
    out = bytearray()
    while len(out) < n:
        out += rng.choice(words) + b" "
    return bytes(out[:n])


def build():
    return {
        "small_multi_block": bz2.compress(text(BLOCK * 2 + 5000, 1), 1),
        "small_run_cross_block": bz2.compress(
            text(BLOCK - 300, 2) + b"R" * 1000 + text(4000, 3), 1
        ),
    }


if __name__ == "__main__":
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for name, blob in build().items():
        assert len(blob) <= 32768, (name, len(blob))
        with open(os.path.join(out, f"{name}.in"), "wb") as f:
            f.write(blob)
