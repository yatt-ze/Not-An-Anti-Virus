#!/bin/sh
# A perfectly ordinary build script — the kind of thing that ships in
# thousands of legitimate open-source repos. Exercises the scanner against
# something that looks like a real script without tripping any signal.
set -eu

echo "Building project..."
cargo build --release
echo "Running tests..."
cargo test --workspace
echo "Done."
