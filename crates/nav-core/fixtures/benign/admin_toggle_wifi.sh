#!/bin/sh
# Ordinary admin-tool fixture: power-cycles Wi-Fi to work around a flaky
# driver reconnect. Exercises legitimate `sudo`/`networksetup` usage that
# must not be confused with a privilege-escalation attempt.
set -eu

IFACE="en0"

sudo networksetup -setairportpower "$IFACE" off
sleep 2
sudo networksetup -setairportpower "$IFACE" on
echo "Wi-Fi power-cycled on $IFACE."
