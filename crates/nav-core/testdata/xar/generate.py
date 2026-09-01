#!/usr/bin/env python3
"""Regenerate the adversarial xar vectors under crates/nav-core/testdata/xar/.

These are synthetic and fully deterministic, unlike the .pkg fixtures (pkgbuild
embeds inode/mtime/uid, so those are committed as static bytes instead).

Each vector targets a specific way a hostile .pkg can try to make the parser
misbehave. Per design doc §3, the "small input, huge materialization" shapes
here are NOT reachable by mutating a valid-file seed corpus, so they are also
seeded deliberately into the parse_xar fuzz target (§11.9).

The four .pkg files alongside these vectors are NOT produced by this script:
they are real pkgbuild/productbuild output, kept as static bytes because those
tools embed inode/mtime/uid and so are not reproducible. Synthetic containers
cannot prove we read what Apple's tooling actually emits.

Usage: python3 generate.py <output-dir>
"""
import os, struct, sys, zlib

XAR_MAGIC = 0x78617221  # 'xar!'

def xar(toc_xml, *, cksum_alg=1, version=1, hdrsize=28,
        toc_c_override=None, toc_u_override=None, heap=b"", compress=True):
    """Build a xar file. Overrides let a header lie about its own TOC."""
    body = zlib.compress(toc_xml, 9) if compress else toc_xml
    toc_c = len(body) if toc_c_override is None else toc_c_override
    toc_u = len(toc_xml) if toc_u_override is None else toc_u_override
    hdr = struct.pack(">IHHQQI", XAR_MAGIC, hdrsize, version, toc_c, toc_u, cksum_alg)
    return hdr + body + heap

OK_TOC = (b'<?xml version="1.0"?><xar><toc><file id="1"><name>PackageInfo</name>'
          b'<type>file</type><data><offset>0</offset><length>4</length><size>4</size>'
          b'<encoding style="application/octet-stream"/></data></file></toc></xar>')

def build():
    c = {}
    c["valid_minimal"]    = xar(OK_TOC, heap=b"DATA")

    # --- header-level abuse -------------------------------------------------
    c["truncated_header"] = xar(OK_TOC)[:20]          # shorter than the 28-byte header
    c["bad_magic"]        = b"NOTX" + xar(OK_TOC)[4:]
    c["hdrsize_absurd"]   = xar(OK_TOC, hdrsize=0xFFFF)  # TOC would start past EOF
    c["hdrsize_zero"]     = xar(OK_TOC, hdrsize=0)       # TOC overlaps the header
    c["toc_c_past_eof"]   = xar(OK_TOC, toc_c_override=1 << 40)
    c["toc_u_absurd"]     = xar(OK_TOC, toc_u_override=1 << 40)  # declared-size bomb
    c["toc_not_zlib"]     = xar(b"not a zlib stream at all", compress=False)
    c["toc_empty"]        = xar(b"", compress=False, toc_c_override=0, toc_u_override=0)
    c["version_absurd"]   = xar(OK_TOC, version=0xFFFF)

    # --- TOC content abuse --------------------------------------------------
    c["toc_not_xml"]      = xar(b"\x00\x01\x02 binary junk, inflates fine, isn't xml")
    c["toc_unclosed"]     = xar(b'<?xml version="1.0"?><xar><toc><file id="1"><name>x')

    # 400 bytes -> 2000 nesting levels. Exercises the §6.2 recursion ceiling.
    deep = (b'<?xml version="1.0"?><xar><toc>'
            + b'<file><name>d</name><type>directory</type>' * 2000
            + b'</file>' * 2000 + b'</toc></xar>')
    c["deep_nesting"]     = xar(deep)

    # 6.5 KB -> 50,000 sibling entries. Exercises the entry-count ceiling.
    wide = (b'<?xml version="1.0"?><xar><toc>'
            + b'<file><name>f</name><type>file</type></file>' * 50000
            + b'</toc></xar>')
    c["wide_toc"]         = xar(wide)

    # --- heap-pointer abuse -------------------------------------------------
    c["heap_past_eof"]    = xar(
        b'<?xml version="1.0"?><xar><toc><file id="1"><name>Scripts</name><type>file</type>'
        b'<data><offset>999999999</offset><length>999999999</length><size>1</size>'
        b'<encoding style="application/octet-stream"/></data></file></toc></xar>', heap=b"short")

    # A tiny heap blob declaring a 4 MiB expansion: the budget must stop this.
    blob = zlib.compress(b"\x00" * (4 << 20), 9)
    c["heap_entry_bomb"]  = xar(
        b'<?xml version="1.0"?><xar><toc><file id="1"><name>PackageInfo</name><type>file</type>'
        b'<data><offset>0</offset><length>' + str(len(blob)).encode() +
        b'</length><size>4194304</size><encoding style="application/x-gzip"/>'
        b'</data></file></toc></xar>', heap=blob)

    # offset+length overflows u64 when added.
    c["offset_overflow"]  = xar(
        b'<?xml version="1.0"?><xar><toc><file id="1"><name>PackageInfo</name><type>file</type>'
        b'<data><offset>18446744073709551615</offset><length>18446744073709551615</length>'
        b'<size>1</size><encoding style="application/octet-stream"/></data></file></toc></xar>',
        heap=b"x")
    return c

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out, exist_ok=True)
    for name, blob in build().items():
        open(os.path.join(out, name + ".xar"), "wb").write(blob)
        print(f"{name:20s} {len(blob):8d} bytes")
