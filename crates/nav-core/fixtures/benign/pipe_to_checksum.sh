#!/bin/sh
# Synthetic benign fixture: verifies a downloaded archive's checksum and
# picks a random sample file, exercising checksum/shuffle tools whose names
# start with "sh"/"bash" so they must not be confused with pipe-to-shell.
set -eu

echo "abc123  archive.tar.gz" | shasum -a 256 --check --status
sha256sum archive.tar.gz | sha256sum
find . -type f | shuf -n 1
