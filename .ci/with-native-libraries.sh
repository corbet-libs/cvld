#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
: "${CARGO_TARGET_DIR:?persistent target required}"
: "${CI_COMMIT_SHA:?exact source required}"
export CVLD_CI_WORKER_PATH="$PATH"
reports="$CARGO_TARGET_DIR/ci-receipts/$CI_COMMIT_SHA"
mkdir -p "$reports"
# Resolve tool inputs only on the worker; retain this exact environment receipt.
# Product Cargo/npm snapshots are not updated by entering the native shell.
nix flake lock
cp flake.lock "$reports/native-libraries.lock"
exec nix develop --max-jobs "${CI_NIX_JOBS:-1}" --cores "${CARGO_BUILD_JOBS:-2}" --no-write-lock-file .#ci --command bash -euo pipefail -c '
  export PATH="$CVLD_CI_WORKER_PATH:$PATH"
  pkg-config --version
  pkg-config --modversion openssl
  exec "$@"
' -- "$@"
