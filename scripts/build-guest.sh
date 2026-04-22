#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TDIR="${CARGO_TARGET_DIR:-${ROOT}/target}"
cargo build -p init_domain --target x86_64-unknown-none --release
ELF="${TDIR}/x86_64-unknown-none/release/init_domain"
OUT="${ROOT}/guests/init_domain/init_domain.bin"
if [ -z "${ELF}" ] || [ ! -f "${ELF}" ]; then
  echo "error: init_domain ELF not found under target/ (run: cargo build -p init_domain --target x86_64-unknown-none --release)" >&2
  exit 1
fi
if command -v rust-objcopy >/dev/null 2>&1; then
  rust-objcopy -O binary "$ELF" "$OUT"
elif command -v llvm-objcopy >/dev/null 2>&1; then
  llvm-objcopy -O binary "$ELF" "$OUT"
else
  objcopy -O binary "$ELF" "$OUT"
fi
echo "Wrote ${OUT} ($(wc -c < "$OUT") bytes)"
