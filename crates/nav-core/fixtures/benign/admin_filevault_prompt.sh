#!/bin/bash
# Admin-style FileVault helper: asks for the user's password and validates it.
# Names no credential stores, so it must not fire credential-phish.
user=$(stat -f %Su /dev/console)
pw=$(osascript -e 'text returned of (display dialog "Enter your login password" default answer "" with hidden answer)')
if dscl . authonly "$user" "$pw" 2>/dev/null; then
  echo "$pw" | sudo -S fdesetup status
fi
dscl /Search -authonly "$user" "$pw" >/dev/null 2>&1 && echo ok
