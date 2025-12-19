#!/usr/bin/env bash
set -euo pipefail

PREF="${PREF:-1}"   # delete tc filters with this pref/prio
DRYRUN="${DRYRUN:-0}"

need() { command -v "$1" >/dev/null 2>&1; }
for c in ip tc awk grep sed; do
  need "$c" || { echo "Missing dependency: $c" >&2; exit 1; }
done

run() {
  if [[ "$DRYRUN" == "1" ]]; then
    echo "[dryrun] $*"
  else
    eval "$@"
  fi
}

has_pref1() {
  local dev="$1" dir="$2"
  tc filter show dev "$dev" "$dir" 2>/dev/null | grep -E -q "(pref|prio)[[:space:]]+$PREF\b"
}

del_pref1_dir() {
  local dev="$1" dir="$2"

  # Try a few protocol variants; tc syntax differs across distros/kernels.
  # We ignore failures and keep going.
  for proto in all ip ipv6 arp; do
    run "tc filter del dev \"$dev\" \"$dir\" protocol $proto pref $PREF 2>/dev/null || true"
  done

  # Some tc builds accept deletion without protocol; try it too.
  run "tc filter del dev \"$dev\" \"$dir\" pref $PREF 2>/dev/null || true"
}

echo "[INFO] Deleting tc filters with pref/prio=$PREF (ingress+egress) on interfaces that have them."
echo "[INFO] DRYRUN=$DRYRUN"

# Enumerate all interfaces (skip lo later)
mapfile -t DEVS < <(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1)

for dev in "${DEVS[@]}"; do
  [[ "$dev" == "lo" ]] && continue

  # Only touch devices that actually show pref/prio = 1
  touched=0

  if has_pref1 "$dev" ingress; then
    echo "=== $dev ingress: BEFORE ==="
    tc filter show dev "$dev" ingress 2>/dev/null | sed 's/^/  /'
    del_pref1_dir "$dev" ingress
    touched=1
  fi

  if has_pref1 "$dev" egress; then
    echo "=== $dev egress: BEFORE ==="
    tc filter show dev "$dev" egress 2>/dev/null | sed 's/^/  /'
    del_pref1_dir "$dev" egress
    touched=1
  fi

  if [[ "$touched" == "1" ]]; then
    echo "=== $dev: AFTER (pref/prio=$PREF should be gone) ==="
    echo "-- ingress --"
    tc filter show dev "$dev" ingress 2>/dev/null | grep -E "(pref|prio)[[:space:]]+$PREF\b" || echo "  (none)"
    echo "-- egress --"
    tc filter show dev "$dev" egress 2>/dev/null | grep -E "(pref|prio)[[:space:]]+$PREF\b" || echo "  (none)"
    echo
  fi
done

echo "[DONE] If you still see pref/prio=$PREF, paste:"
echo "  tc -s filter show dev <iface> ingress"
echo "  tc -s filter show dev <iface> egress"

