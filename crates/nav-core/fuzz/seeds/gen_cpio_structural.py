#!/usr/bin/env python3
"""Write structurally distinct seeds for parse_cpio (§11.9, #199).

testdata/cpio/ covers header abuse and odc truncation; these add newc
alignment residues, the 070702 magic, mixed formats, non-file modes, names
past the header lookahead, newc padding truncation, the byte-ceiling
boundary, and valid archives padded so the harness's XOR-of-bytes chunk size
splits them at chosen points. Each fits the nightly -max_len of 16384.

Usage: gen_cpio_structural.py <output-dir>
"""
import os
import sys
from functools import reduce

TRAILER = b"TRAILER!!!"
MAX_LEN = 16384
HARNESS_MAX_TOTAL = 1 << 20


def odc(name, data=b"", mode=0o100644, filesize=None):
    nb = name + b"\0"
    fs = len(data) if filesize is None else filesize
    h = (b"070707" + b"000000" + b"000001" + b"%06o" % mode + b"000000" * 2
         + b"000001" + b"000000" + b"%011o" % 0 + b"%06o" % len(nb) + b"%011o" % fs)
    return h + nb + data


def newc(name, data=b"", mode=0o100644, magic=b"070701", at=0):
    """`at` is the archive offset the entry starts at; padding is to it."""
    nb = name + b"\0"
    fields = [1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nb), 0]
    h = magic + b"".join(b"%08X" % v for v in fields)
    head = h + nb
    head += b"\0" * (-(at + len(head)) % 4)
    body = data + b"\0" * (-(at + len(head) + len(data)) % 4)
    return head + body


def newc_archive(members, magic=b"070701"):
    out = b""
    for name, data, mode in members + [(TRAILER, b"", 0)]:
        out += newc(name, data, mode, magic, len(out))
    return out


def xor(blob):
    return reduce(lambda a, b: a ^ b, blob, 0)


def with_chunk(archive, chunk):
    """Appends one byte after the trailer so the XOR of all bytes is `chunk`."""
    return archive + bytes([xor(archive) ^ chunk])


def build():
    s = {}
    # Every name and data length residue mod 4.
    align = [(b"n" * n, b"d" * d, 0o100644) for n in range(1, 5) for d in range(5)]
    s["newc_align_residues"] = newc_archive(align)
    s["newc_crc_valid"] = newc_archive([(b"preinstall", b"#!/bin/sh\nexit 0\n", 0o100755)],
                                       magic=b"070702")

    script = b"#!/bin/sh\nexit 0\n"
    mixed = odc(b"a", script)
    mixed += newc(b"b", script, at=len(mixed))
    mixed += odc(TRAILER)
    s["mixed_odc_newc"] = mixed

    s["odc_modes"] = (odc(b"dir", mode=0o040755) + odc(b"dir/link", b"../x", 0o120755)
                      + odc(b"dir/fifo", mode=0o010644) + odc(b"dir/x", script, 0o100755)
                      + odc(TRAILER))

    long_name = b"Scripts/" + b"p" * 300
    s["odc_long_name"] = odc(long_name, script) + odc(TRAILER)
    s["newc_long_name"] = newc_archive([(long_name, script, 0o100644)])

    # Past the harness's 64-entry cap, each with a trailer, inside -max_len.
    s["odc_entries_past_cap"] = b"".join(odc(b"a") for _ in range(100)) + odc(TRAILER)
    s["newc_entries_past_cap"] = newc_archive([(b"a", b"", 0o100644)] * 100)

    # newc cut inside the name padding, and inside the data padding.
    one = newc(b"ab", b"x")
    s["newc_cut_in_name_pad"] = one[:110 + 3 + 1]
    s["newc_cut_in_data_pad"] = one[:116 + 1 + 1]
    s["odc_cut_in_trailer_name"] = odc(b"a", script) + odc(TRAILER)[:80]

    # Declared size exactly at, and one past, the harness's total-byte ceiling.
    s["odc_size_at_byte_cap"] = odc(b"big", b"x" * 64, filesize=HARNESS_MAX_TOTAL)
    s["odc_size_past_byte_cap"] = (odc(b"a", b"x") +
                                   odc(b"big", filesize=HARNESS_MAX_TOTAL))

    # Stream split points: byte at a time, mid-magic, at the odc and newc
    # header ends, and just past each.
    for base in ("newc_align_residues", "mixed_odc_newc", "odc_long_name"):
        for chunk in (1, 3, 6, 76, 77, 110, 111):
            s[f"{base}_chunk{chunk}"] = with_chunk(s[base], chunk)
    return s


if __name__ == "__main__":
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for name, blob in build().items():
        assert len(blob) <= MAX_LEN, name
        with open(os.path.join(out, f"{name}.cpio"), "wb") as f:
            f.write(blob)
