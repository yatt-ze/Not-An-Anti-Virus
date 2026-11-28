#!/usr/bin/env python3
"""Regenerate the PNG differential corpus in crates/nav-core/testdata/png/.

Writes the synthetic vectors, then parses every *.png in the directory with
the reference walker below (Python's struct and zlib, not nav-core) and
writes expected.txt: one line per file, "<name> malformed" or
"<name> ok <start>..<end> ...", the byte ranges nav_core::png should return.

sips.png is real ImageIO output and is not rebuilt unless --sips is given
(macOS only); its bytes are committed as they are.

Usage: python3 generate.py <output-dir> [--sips]
"""
import os, random, struct, subprocess, sys, tempfile, zlib

SIG = b"\x89PNG\r\n\x1a\n"


def chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def ihdr(w, h):
    return chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))


def pixels(w, h, seed):
    rng = random.Random(seed)
    return b"".join(b"\0" + bytes(rng.randrange(256) for _ in range(3 * w)) for _ in range(h))


def png(w, h, middle, idat=None):
    idat = zlib.compress(pixels(w, h, w * h), 9) if idat is None else idat
    return SIG + ihdr(w, h) + b"".join(middle) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


XMP = b"XML:com.adobe.xmp\0\0\0\0\0" + b"<rdf:Description about=''/>\n" * 8


def apng():
    w, h = 8, 8
    first = zlib.compress(pixels(w, h, 1), 9)
    second = zlib.compress(pixels(w, h, 2), 9)
    fctl = lambda seq: chunk(b"fcTL", struct.pack(">IIIIIHHBB", seq, w, h, 0, 0, 1, 10, 0, 0))
    half = len(second) // 2
    return (
        SIG + ihdr(w, h)
        + chunk(b"acTL", struct.pack(">II", 2, 0))
        + fctl(0)
        + chunk(b"IDAT", first)
        + fctl(1)
        # one frame's stream split over two fdATs; only the first has a header
        + chunk(b"fdAT", struct.pack(">I", 2) + second[:half])
        + chunk(b"fdAT", struct.pack(">I", 3) + second[half:])
        + chunk(b"IEND", b"")
    )


def build():
    c = {}
    c["plain"] = png(8, 8, [])
    c["xmp_itxt"] = png(16, 16, [chunk(b"iTXt", XMP)])
    c["iccp"] = png(8, 8, [chunk(b"iCCP", b"sRGB\0\0" + zlib.compress(b"profile " * 40))])
    c["ztxt"] = png(8, 8, [chunk(b"zTXt", b"Comment\0\0" + zlib.compress(b"a comment " * 30))])
    c["itxt_compressed"] = png(
        8, 8, [chunk(b"iTXt", b"Title\0\x01\0en\0Titel\0" + zlib.compress(b"title " * 30))]
    )
    c["apng"] = apng()
    plain = c["plain"]
    c["bad_crc"] = plain[:-4] + bytes([plain[-4] ^ 1]) + plain[-3:]  # IEND's CRC
    c["trailing_data"] = c["plain"] + b"\0junk"
    c["bad_zlib_header"] = png(8, 8, [], idat=b"\x78\x9d" + zlib.compress(pixels(8, 8, 64))[2:])
    return c


def sips_png(out):
    """A real encoder's PNG: ImageIO re-encoding a generated 24-bit BMP."""
    w, h = 16, 16
    row = (3 * w + 3) & ~3
    data = b"".join(bytes((x * 16, y * 16, 128)) for y in range(h) for x in range(w))
    rows = b"".join(data[y * 3 * w:(y + 1) * 3 * w].ljust(row, b"\0") for y in range(h))
    bmp = (b"BM" + struct.pack("<IHHI", 54 + len(rows), 0, 0, 54)
           + struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(rows), 2835, 2835, 0, 0) + rows)
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "in.bmp")
        with open(src, "wb") as f:
            f.write(bmp)
        subprocess.run(["sips", "-s", "format", "png", src, "--out", out],
                       check=True, stdout=subprocess.DEVNULL)


def zlib_header(b):
    return (len(b) >= 2 and b[0] & 0x0F == 8 and b[0] >> 4 <= 7
            and (b[0] << 8 | b[1]) % 31 == 0 and not b[1] & 0x20)


def reference(data):
    """Ranges of the compressed payloads, or None if malformed."""
    if data[:8] != SIG:
        return None
    pos, prev, ranges, index = 8, None, [], 0
    while index < 65536:
        if pos + 8 > len(data):
            return None
        length, kind = struct.unpack(">I4s", data[pos:pos + 8])
        if length > 0x7FFFFFFF or not kind.isalpha() or not kind.isascii():
            return None
        start, end = pos + 8, pos + 8 + length
        if end + 4 > len(data):
            return None
        body = data[start:end]
        if struct.unpack(">I", data[end:end + 4])[0] != zlib.crc32(kind + body):
            return None
        if (index == 0) != (kind == b"IHDR") or (index == 0 and length != 13):
            return None
        if kind == b"IEND":
            return ranges if length == 0 and end + 4 == len(data) else None
        offset = None
        if kind == b"IDAT":
            offset = 0
        elif kind == b"fdAT":
            if length < 4:
                return None
            offset = 4
        elif kind in (b"zTXt", b"iCCP", b"iTXt"):
            nul = body.find(b"\0", 0, 80)
            if nul < 1 or nul + 1 >= len(body):
                return None
            if kind == b"iTXt":
                flag = body[nul + 1]
                if nul + 2 >= len(body) or body[nul + 2] != 0 or flag > 1:
                    return None
                lang = body.find(b"\0", nul + 3)
                trans = body.find(b"\0", lang + 1) if lang >= 0 else -1
                if trans < 0:
                    return None
                offset = trans + 1 if flag == 1 else None
            else:
                if body[nul + 1] != 0:
                    return None
                offset = nul + 2
        if offset is not None:
            continues = kind == prev and kind in (b"IDAT", b"fdAT")
            if not continues and not zlib_header(body[offset:]):
                return None
            ranges.append((start + offset, end))
        prev = kind
        pos = end + 4
        index += 1
    return None


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for name, data in build().items():
        with open(os.path.join(out, name + ".png"), "wb") as f:
            f.write(data)
    if "--sips" in sys.argv[2:]:
        sips_png(os.path.join(out, "sips.png"))
    lines = []
    for name in sorted(os.listdir(out)):
        if not name.endswith(".png"):
            continue
        with open(os.path.join(out, name), "rb") as f:
            ranges = reference(f.read())
        if ranges is None:
            lines.append(f"{name} malformed")
        else:
            lines.append(" ".join([name, "ok"] + [f"{s}..{e}" for s, e in ranges]))
    with open(os.path.join(out, "expected.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
