#!/usr/bin/env python3
"""Regenerate adversarial cpio vectors under crates/nav-core/testdata/cpio/.

NAV reaches .pkg install-script contents through a gzip'd cpio archive stored
in the xar heap (design doc §5.2, §6.1). pkgbuild emits the *odc* format
(magic 070707, 76-byte octal header), not the newc most cpio code assumes, so
both are covered here.

The parser is metadata-only and never writes extracted files to disk, so the
traversal/absolute-path cases below are about reporting names safely, not
about a write primitive.

Three vectors are NOT produced by this script and are kept as static bytes,
because the tools that made them embed inode/mtime/uid and so are not
reproducible: real_scripts.cpio (the actual Scripts archive from a
pkgbuild-produced .pkg) and system_odc.cpio / system_newc.cpio (written by
/usr/bin/cpio). Synthetic headers alone cannot prove we read what the real
tools emit.

Usage: python3 gen_cpio_adversarial.py <output-dir>
"""
import os, sys

TRAILER = "TRAILER!!!"

def odc(name, data=b"", *, mode=0o100644, namesize=None, filesize=None, magic=b"070707"):
    """odc: magic(6) dev(6) ino(6) mode(6) uid(6) gid(6) nlink(6) rdev(6)
       mtime(11) namesize(6) filesize(11) = 76 bytes, then name+NUL, then data."""
    nb = (name if isinstance(name, bytes) else name.encode()) + b"\x00"
    ns = len(nb) if namesize is None else namesize
    fs = len(data) if filesize is None else filesize
    h = (magic + b"000000" + b"000001" + f"{mode:06o}".encode() + b"000000" * 2
         + b"000001" + b"000000" + f"{0:011o}".encode()
         + f"{ns:06o}".encode() + f"{fs:011o}".encode())
    return h + nb + data

def newc(name, data=b"", *, mode=0o100644, namesize=None, filesize=None, magic=b"070701"):
    """newc: magic(6) + 13 x 8 hex fields = 110 bytes; name and data each
       padded so the following field starts on a 4-byte boundary."""
    nb = (name if isinstance(name, bytes) else name.encode()) + b"\x00"
    ns = len(nb) if namesize is None else namesize
    fs = len(data) if filesize is None else filesize
    f = [1, mode, 0, 0, 1, 0, fs, 0, 0, 0, 0, ns, 0]
    h = magic + b"".join(f"{v:08X}".encode() for v in f)
    pad = lambda b, base: b + b"\x00" * (-(len(b) + base) % 4)
    return pad(h + nb, 0) + pad(data, 0)

def build():
    c = {}
    good = odc("preinstall", b"#!/bin/sh\nexit 0\n") + odc(TRAILER)
    c["odc_valid"]            = good
    c["newc_valid"]           = newc("preinstall", b"#!/bin/sh\nexit 0\n") + newc(TRAILER)

    # --- header abuse -------------------------------------------------------
    c["bad_magic"]            = odc("f", b"x", magic=b"079999") + odc(TRAILER)
    c["odc_non_octal"]        = odc("f", b"x").replace(b"000001", b"zzzzzz", 1) + odc(TRAILER)
    c["newc_non_hex"]         = newc("f", b"x").replace(b"00000001", b"ZZZZZZZZ", 1)
    c["odc_namesize_zero"]    = odc("f", b"x", namesize=0) + odc(TRAILER)
    c["odc_namesize_huge"]    = odc("f", b"x", namesize=0o777777) + odc(TRAILER)
    c["odc_filesize_huge"]    = odc("f", b"", filesize=0o77777777777) + odc(TRAILER)
    c["newc_namesize_huge"]   = newc("f", b"x", namesize=0xFFFFFFFF)
    c["newc_filesize_huge"]   = newc("f", b"", filesize=0xFFFFFFFF)

    # --- truncation ---------------------------------------------------------
    c["odc_truncated_header"] = good[:40]
    c["odc_truncated_name"]   = good[:80]
    c["odc_truncated_data"]   = good[:90]
    c["odc_no_trailer"]       = odc("preinstall", b"#!/bin/sh\nexit 0\n")
    c["empty"]                = b""
    c["odc_trailer_only"]     = odc(TRAILER)

    # --- name abuse (metadata-only parser: must report safely, never write) --
    c["odc_name_traversal"]   = odc("../../../etc/passwd", b"x") + odc(TRAILER)
    c["odc_name_absolute"]    = odc("/etc/passwd", b"x") + odc(TRAILER)
    c["odc_name_non_utf8"]    = odc(b"bad\xff\xfename", b"x") + odc(TRAILER)

    # --- entry-count ceiling ------------------------------------------------
    c["odc_entry_bomb"]       = b"".join(odc("a") for _ in range(2000)) + odc(TRAILER)
    return c

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out, exist_ok=True)
    for name, blob in build().items():
        open(os.path.join(out, name + ".cpio"), "wb").write(blob)
        print(f"{name:24s} {len(blob):8d} bytes")
