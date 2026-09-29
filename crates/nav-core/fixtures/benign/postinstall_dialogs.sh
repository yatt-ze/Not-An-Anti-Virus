#!/bin/sh
# Benign installer postinstall: prompts the user and quits an app.
osascript -e 'display dialog "Please click Allow in System Settings to finish setup." buttons {"OK"}'
osascript -e 'tell application "Foo" to quit'
osascript -e 'do shell script "kextunload -b com.example.x" with administrator privileges'
exit 0
