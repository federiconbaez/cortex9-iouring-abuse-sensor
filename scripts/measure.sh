#!/usr/bin/env bash
# Reproducible measurement entrypoint. Prints the acceptance numbers (detection,
# FPR, blindness) and the policy-cost microbenchmark, then exits non-zero if the
# acceptance thresholds are not met.
#
#   detection >= 11/12, FPR <= 2% over 50 legit io_uring workloads,
#   syscall-layer monitor: classic 12/12 intercepted, io_uring 0/12.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo run --release --quiet -- measure --iters "${ITERS:-200000}" "$@"
