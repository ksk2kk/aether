#!/usr/bin/env bash
# Boot the Multiboot2 ISO produced by `make iso` (Hypercore + `guest` module = init_domain.bin).
# Prefers KVM + nested VMX when /dev/kvm is usable; falls back to TCG for bring-up without hardware.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ISO="${1:-${ROOT}/build/os-x86_64.iso}"

if [[ ! -f "${ISO}" ]]; then
  echo "error: ISO not found: ${ISO}" >&2
  echo "       Run: make iso   (from ${ROOT})" >&2
  exit 1
fi

args=(
  -machine q35
  -cdrom "${ISO}"
  -serial stdio
  -display none
  -m 128M
)

if [[ -r /dev/kvm ]] && command -v qemu-system-x86_64 >/dev/null 2>&1; then
  # Nested VMX for Hypercore under host KVM
  args=( -enable-kvm -cpu host,+vmx "${args[@]}" )
  echo "[run-qemu] Using KVM (host CPU +vmx)" >&2
else
  args=( -accel tcg -cpu max "${args[@]}" )
  echo "[run-qemu] /dev/kvm not available: using TCG. VMX may still work depending on QEMU build." >&2
fi

exec qemu-system-x86_64 "${args[@]}"
