#!/usr/bin/env python3
"""Write valid long-comment and Zip64 seeds for parse_zip (§11.9).

Each fits the nightly -max_len of 66560. Usage: gen_zip_long.py <output-dir>
"""
import os
import struct
import sys
import zlib

MAX_COMMENT = 0xFFFF
FILLER = bytes(range(32, 127))


def filler(n):
    return (FILLER * (n // len(FILLER) + 1))[:n]


def entry(name=b"a.sh", data=b"#!/bin/sh\nexit 0\n", offset=0):
    crc = zlib.crc32(data)
    sizes = struct.pack("<III", crc, len(data), len(data))
    local = struct.pack("<IHHHHH", 0x04034B50, 20, 0, 0, 0, 0) + sizes
    local += struct.pack("<HH", len(name), 0) + name + data
    central = struct.pack("<IHHHHHH", 0x02014B50, 20, 20, 0, 0, 0, 0) + sizes
    central += struct.pack("<HHHHHII", len(name), 0, 0, 0, 0, 0, offset) + name
    return local, central


def end(count, size, start, comment=b""):
    return struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, count, count, size, start,
                       len(comment)) + comment


def zip64_end(count, size, start, at, comment=b""):
    record = struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, count, count,
                         size, start)
    locator = struct.pack("<IIQI", 0x07064B50, 0, at, 1)
    return record + locator + end(0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, comment)


def build():
    local, central = entry()
    body = local + central
    start, size = len(local), len(central)
    fake = end(1, size, start)
    decoy = filler(30000) + fake + filler(MAX_COMMENT - 30000 - len(fake))

    prefix = filler(256)
    shifted_local, shifted_central = entry(offset=0)
    shifted = prefix + shifted_local + shifted_central
    return {
        "long_comment": body + end(1, size, start, filler(MAX_COMMENT)),
        "end_record_in_comment": body + end(1, size, start, decoy),
        "end_past_search_window": body + end(1, size, start) + filler(MAX_COMMENT + 1),
        "zip64_long_comment": body + zip64_end(1, size, start, len(body),
                                               filler(MAX_COMMENT)),
        "zip64_prefix_long_comment": shifted + zip64_end(1, size, start, len(shifted),
                                                         filler(MAX_COMMENT)),
    }


if __name__ == "__main__":
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for name, blob in build().items():
        assert len(blob) <= 66560, name
        with open(os.path.join(out, f"{name}.zip"), "wb") as f:
            f.write(blob)
