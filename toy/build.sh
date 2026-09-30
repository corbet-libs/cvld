#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
python3 toy/prepare.py
cc -O2 -Wall -Wextra -Werror -c toy/meter.c -o toy/.build/meter.o
cargo rustc --locked --features development-gate --bin cvld -- \
  -C "link-arg=$PWD/toy/.build/meter.o" -C link-arg=-Wl,--wrap=sqlite3_step
# The toy root is new; the copied lock retains the door's exact dependency versions.
cargo build --manifest-path toy/.build/Cargo.toml
