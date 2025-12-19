#!/usr/bin/env bash
set -euo pipefail

OBJ="${1:-tc_flow_log.bpf.o}"
OUT_MAP="${2:-$HOME/lxc_tc_prog_map.tsv}"   # TSV: ifindex<TAB>dir<TAB>prog_id<TAB>ifname

die() { echo "ERROR: $*" >&2; exit 1; }

[[ -f "$OBJ" ]] || die "object not found: $OBJ"
command -v tc >/dev/null || die "tc not found"
command -v ip >/dev/null || die "ip not found"
command -v sudo >/dev/null || die "sudo not found"

# Strip "@ifNN" suffix if present (ip link prints veth peers this way)
base_ifname() {
  local n="$1"
  echo "${n%%@*}"
}

# Parse true BPF prog id from tc output. iproute2 versions differ; try multiple patterns.
get_tc_bpf_prog_id() {
  local dev="$1" dir="$2"
  tc filter show dev "$dev" "$dir" 2>/dev/null \
    | awk '
      /pref[[:space:]]+1/ && /handle[[:space:]]+1/ { inblk=1 }
      inblk && match($0, /\bid[[:space:]]+([0-9]+)/, m) { print m[1]; exit }
      inblk && match($0, /\bprog_id[[:space:]]+([0-9]+)/, m) { print m[1]; exit }
      inblk && match($0, /\bprog-id[[:space:]]+([0-9]+)/, m) { print m[1]; exit }
      { if (inblk && $0 ~ /^[[:space:]]*$/) inblk=0 }
    ' | head -n 1
}

# Collect lxc* names; ip may show "lxc...@if56" so keep raw then normalize.
mapfile -t RAW_IFACES < <(
  ip -o link show \
    | awk -F': ' '{print $2}' | awk '{print $1}' \
    | grep -E '^lxc' \
    | grep -v -E '^lxc_health$' \
    | sort -u
)

# Normalize & uniq
declare -A seen=()
IFACES=()
for r in "${RAW_IFACES[@]}"; do
  b="$(base_ifname "$r")"
  [[ -z "$b" ]] && continue
  if [[ -z "${seen[$b]:-}" ]]; then
    seen[$b]=1
    IFACES+=("$b")
  fi
done

# if you would like to hook only one or two, add here
IFACES=("lxcf100f88ed873")

if [[ ${#IFACES[@]} -eq 0 ]]; then
  echo "No lxc* interfaces found (excluding lxc_health)."
  exit 0
fi

# Write map header using sudo tee (avoids redirect permission issues)
echo -e "#ifindex\tdir\tprog_id\tifname" | sudo tee "$OUT_MAP" >/dev/null

for dev in "${IFACES[@]}"; do
  echo "==> Hooking $dev ingress+egress"

  sudo tc qdisc add dev "$dev" clsact 2>/dev/null || true

  sudo tc filter replace dev "$dev" ingress pref 1 handle 1 \
    bpf da obj "$OBJ" sec "classifier/ingress"

  sudo tc filter replace dev "$dev" egress pref 1 handle 1 \
    bpf da obj "$OBJ" sec "classifier/egress"

  ifidx_path="/sys/class/net/$dev/ifindex"
  [[ -f "$ifidx_path" ]] || die "No ifindex at $ifidx_path (dev name mismatch?)"
  ifidx="$(cat "$ifidx_path")"

  in_id="$(get_tc_bpf_prog_id "$dev" ingress || true)"
  eg_id="$(get_tc_bpf_prog_id "$dev" egress  || true)"

  if [[ -z "${in_id}" || -z "${eg_id}" ]]; then
    echo "WARN: cannot parse prog_id for $dev (ingress='${in_id:-}', egress='${eg_id:-}')." >&2
    echo "      Paste these for me to adjust parsing:" >&2
    echo "        tc filter show dev $dev ingress" >&2
    echo "        tc filter show dev $dev egress" >&2
  fi

  # dir: 1 ingress, 2 egress (match BPF logs)
  [[ -n "$in_id" ]] && echo -e "${ifidx}\t1\t${in_id}\t${dev}" | sudo tee -a "$OUT_MAP" >/dev/null
  [[ -n "$eg_id" ]] && echo -e "${ifidx}\t2\t${eg_id}\t${dev}" | sudo tee -a "$OUT_MAP" >/dev/null
done

echo "==> Wrote prog_id map to: $OUT_MAP"
echo "==> Map tail:"
sudo tail -n 20 "$OUT_MAP" || true
