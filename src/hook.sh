#!/usr/bin/env bash
set -euo pipefail

OBJ="${1:-tc_flow_log.bpf.o}"
OUT_MAP="${2:-$HOME/lxc_tc_prog_map.tsv}"   # TSV: ifindex<TAB>dir<TAB>prog_id<TAB>ifname

# Optional env overrides
PREF="${PREF:-1}"
HANDLE="${HANDLE:-1}"        # you can set HANDLE=0x1 too
IF_REGEX="${IF_REGEX:-^lxc}" # which ifnames to hook
ONLY_IFACES="${ONLY_IFACES:-"lxcf100f88ed873"}" # space-separated list: "lxc123 lxc456"

die() { echo "ERROR: $*" >&2; exit 1; }

[[ -f "$OBJ" ]] || die "object not found: $OBJ"
command -v tc   >/dev/null || die "tc not found"
command -v ip   >/dev/null || die "ip not found"
command -v sudo >/dev/null || die "sudo not found"
command -v awk  >/dev/null || die "awk not found"
command -v sed  >/dev/null || die "sed not found"
command -v grep >/dev/null || die "grep not found"

# Strip "@ifNN" suffix if present
base_ifname() {
  local n="$1"
  echo "${n%%@*}"
}

# Return a regex that matches handle in tc output (accept "1" or "0x1" forms when applicable)
handle_regex() {
  local h="$1"
  # normalize common case: 1 vs 0x1
  case "$h" in
    0x*|0X*)
      local dec="${h#0x}"; dec="${dec#0X}"
      # if hex is just "1", accept both
      if [[ "$dec" =~ ^[0-9a-fA-F]+$ ]]; then
        # best-effort: if hex is all digits and small, accept both textual variants
        if [[ "$dec" == "1" ]]; then
          echo "(0x)?1"
        else
          # fall back to matching the exact token text
          echo "$h"
        fi
      else
        echo "$h"
      fi
      ;;
    *)
      if [[ "$h" == "1" ]]; then
        echo "(0x)?1"
      else
        echo "$h"
      fi
      ;;
  esac
}

HANDLE_RE="$(handle_regex "$HANDLE")"

# Parse BPF prog id from tc output (iproute2 variants differ).
# We try to match the specific block by pref + handle, then extract:
#   " id N" or "prog_id N" or "prog-id N"
get_tc_bpf_prog_id() {
  local dev="$1" dir="$2"
  tc filter show dev "$dev" "$dir" 2>/dev/null \
    | awk -v pref="$PREF" -v handle_re="$HANDLE_RE" '
      function ok_block(line) {
        return (line ~ ("pref[[:space:]]+" pref)) && (line ~ ("handle[[:space:]]+" handle_re))
      }
      ok_block($0) {
        if (match($0, /\bid[[:space:]]+([0-9]+)/, m))      { print m[1]; exit }
        if (match($0, /\bprog_id[[:space:]]+([0-9]+)/, m)) { print m[1]; exit }
        if (match($0, /\bprog-id[[:space:]]+([0-9]+)/, m)) { print m[1]; exit }
      }
    ' | head -n 1
}

# Collect lxc* ifnames, strip @peer, drop lxc_health
collect_ifaces() {
  ip -o link show \
    | awk -F': ' '$2 ~ /^[^ ]+/ {print $2}' \
    | awk '{print $1}' \
    | while read -r raw; do
        b="$(base_ifname "$raw")"
        [[ -n "$b" ]] || continue
        echo "$b"
      done \
    | grep -E "$IF_REGEX" \
    | grep -v '^lxc_health$' \
    | sort -u
}

# Decide target interfaces
IFACES=()
if [[ -n "$ONLY_IFACES" ]]; then
  # user provided explicit list
  for x in $ONLY_IFACES; do
    IFACES+=("$(base_ifname "$x")")
  done
else
  mapfile -t IFACES < <(collect_ifaces)
fi

if [[ ${#IFACES[@]} -eq 0 ]]; then
  echo "No interfaces found (regex=$IF_REGEX, excluding lxc_health)."
  exit 0
fi

# Write header (use sudo tee to avoid redirect permission issues if OUT_MAP is protected)
echo -e "#ifindex\tdir\tprog_id\tifname" | sudo tee "$OUT_MAP" >/dev/null

for dev in "${IFACES[@]}"; do
  echo "==> Hooking $dev ingress+egress (pref=$PREF handle=$HANDLE)"

  # Ensure clsact exists (idempotent)
  sudo tc qdisc replace dev "$dev" clsact

  # Attach BPF
  sudo tc filter replace dev "$dev" ingress pref "$PREF" handle "$HANDLE" \
    bpf da obj "$OBJ" sec "classifier/ingress"

  sudo tc filter replace dev "$dev" egress  pref "$PREF" handle "$HANDLE" \
    bpf da obj "$OBJ" sec "classifier/egress"

  ifidx_path="/sys/class/net/$dev/ifindex"
  [[ -f "$ifidx_path" ]] || die "No ifindex at $ifidx_path (dev name mismatch?)"
  ifidx="$(cat "$ifidx_path")"

  in_id="$(get_tc_bpf_prog_id "$dev" ingress || true)"
  eg_id="$(get_tc_bpf_prog_id "$dev" egress  || true)"

  if [[ -z "$in_id" || -z "$eg_id" ]]; then
    echo "WARN: cannot parse prog_id for $dev (ingress='${in_id:-}', egress='${eg_id:-}')." >&2
    echo "      Debug with:" >&2
    echo "        tc filter show dev $dev ingress" >&2
    echo "        tc filter show dev $dev egress" >&2
  fi

  # dir: 1 ingress, 2 egress (match your BPF logs dir values)
  [[ -n "$in_id" ]] && echo -e "${ifidx}\t1\t${in_id}\t${dev}" | sudo tee -a "$OUT_MAP" >/dev/null
  [[ -n "$eg_id" ]] && echo -e "${ifidx}\t2\t${eg_id}\t${dev}" | sudo tee -a "$OUT_MAP" >/dev/null
done

echo "==> Wrote prog_id map to: $OUT_MAP"
echo "==> Map tail:"
sudo tail -n 50 "$OUT_MAP" || true
