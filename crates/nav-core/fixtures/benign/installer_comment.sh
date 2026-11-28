#!/bin/sh
# Installer that explains its own delivery in comments (#318).
# The login shell that ran this script, like the one `curl ... | bash` was typed into,
# may not have read the new profile yet.
  # Or with wget: `wget -qO- https://example.test/install.sh | bash`
set -e
PROFILE="${HOME}/.profile"
echo 'export PATH="$HOME/.tool/bin:$PATH"' >> "$PROFILE"
echo "Done. Open a new terminal."
