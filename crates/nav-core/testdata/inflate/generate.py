#!/usr/bin/env python3
"""Regenerate the differential inflate vectors under crates/nav-core/testdata/inflate/.

Ground truth comes from CPython's zlib (i.e. real zlib), so nav-core's
hand-rolled RFC1951/RFC1950 decoder is checked against a reference
implementation rather than against itself. Deterministic: the RNG is seeded.

Each case pairs <name>.in (compressed) with <name>.out (expected plaintext).
bomb.in deliberately has no .out - it must be rejected as BudgetExceeded.

Usage: python3 gen_inflate_vectors.py <output-dir>
"""
import os, random, sys, zlib

def raw(data, level=6):
    """Raw DEFLATE, no wrapper (wbits=-15)."""
    co = zlib.compressobj(level, zlib.DEFLATED, -15)
    return co.compress(data) + co.flush()

def build():
    random.seed(20260830)
    c = {}
    c["empty"]        = (b"", raw(b""))
    c["hello"]        = (b"hello, world", raw(b"hello, world"))

    # level 0 -> stored blocks (BTYPE=00); >64KiB spans multiple stored blocks
    stored = bytes(random.getrandbits(8) for _ in range(70000))
    c["stored"]       = (stored, raw(stored, 0))

    # small + repetitive -> fixed Huffman (BTYPE=01)
    c["fixed"]        = (b"aaaaaaaabbbbbbbbaaaaaaaa", raw(b"aaaaaaaabbbbbbbbaaaaaaaa", 1))

    # long zero run -> long back-refs, 840:1 ratio
    zeros = b"\x00" * 65536
    c["zeros_64k"]    = (zeros, raw(zeros, 9))

    # varied text -> dynamic Huffman (BTYPE=10)
    words = ["package","install","script","distribution","signature",
             "payload","bundle","launchd","entropy","notarized"]
    text = (" ".join(random.choice(words) for _ in range(4000))).encode()
    c["dynamic_text"] = (text, raw(text, 9))

    # incompressible
    rnd = bytes(random.getrandbits(8) for _ in range(4096))
    c["random_4k"]    = (rnd, raw(rnd, 9))

    # repeating pattern well past 32KiB -> back-refs at max distance, across blocks
    pat = b"NAVxar!TOC" * 8000
    c["window"]       = (pat, raw(pat, 9))

    # RFC1950-wrapped (what a real xar TOC is)
    c["zlib_hello"]   = (b"hello, world", zlib.compress(b"hello, world"))
    toc = (b'<?xml version="1.0" encoding="UTF-8"?>\n<xar><toc><checksum style="sha1">'
           b'<offset>0</offset><size>20</size></checksum></toc></xar>\n')
    c["zlib_toc"]     = (toc, zlib.compress(toc, 9))
    return c

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out, exist_ok=True)
    for name, (plain, comp) in build().items():
        open(os.path.join(out, name + ".out"), "wb").write(plain)
        open(os.path.join(out, name + ".in"), "wb").write(comp)
        ratio = len(plain) / len(comp) if comp else 0
        print(f"{name:14s} in={len(comp):7d} out={len(plain):7d} ratio={ratio:8.1f}")

    # 8 MiB of zeros from ~8 KB. No .out on purpose: expected BudgetExceeded.
    open(os.path.join(out, "bomb.in"), "wb").write(raw(b"\x00" * (8 << 20), 9))
    print(f"{'bomb':14s} in={os.path.getsize(os.path.join(out,'bomb.in')):7d} (no .out: BudgetExceeded)")
