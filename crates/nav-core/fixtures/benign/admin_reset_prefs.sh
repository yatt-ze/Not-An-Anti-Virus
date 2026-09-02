#!/bin/sh
# Ordinary admin-tool fixture: resets a handful of Finder/Dock preferences to
# their defaults and restarts the affected services — a common "un-break my
# Mac" snippet. Legitimate `defaults`/`sudo` usage, no fetch, no persistence.
set -eu

defaults delete com.apple.finder FXPreferredViewStyle 2>/dev/null || true
defaults write com.apple.dock autohide -bool false
sudo defaults write /Library/Preferences/com.apple.loginwindow.plist \
    LoginwindowText "Managed by IT -- contact helpdesk for issues"

killall Dock
killall Finder
echo "Preferences reset."
