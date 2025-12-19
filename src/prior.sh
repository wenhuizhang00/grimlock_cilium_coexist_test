#!/usr/bin/env bash
set -euo pipefail

printf "%-18s %-12s %-8s %-10s %-6s %-8s %s\n" IFACE HOOK PRIO HANDLE CHAIN PROG_ID PROG_NAME

# -------- XDP (no priority) --------
bpftool net 2>/dev/null | awk '
  BEGIN{sec=""}
  /^xdp:/{sec="xdp"; next}
  /^tc:|^flow_dissector:|^netfilter:/{sec=""; next}
  sec=="xdp" && NF>0 {
    iface=$1; sub(/\(.*/, "", iface)
    hook=$2
    id=""
    for(i=1;i<=NF;i++) if($i=="id" && i+1<=NF) id=$(i+1)
    if(id!="") printf "%-18s %-12s %-8s %-10s %-6s %-8s %s\n", iface, hook, "-", "-", "-", id, "-"
  }
'

# -------- TC (priority == tc "pref") --------
mapfile -t ifaces < <(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1)

for dev in "${ifaces[@]}"; do
  for dir in ingress egress; do
    tc -d filter show dev "$dev" "$dir" 2>/dev/null | awk -v dev="$dev" -v dir="$dir" '
      function reset_block() {
        pref="-"; handle="-"; chain="0"; id=""; name="-"; printed=0;
      }
      function try_parse_kv() {
        for (i=1; i<=NF; i++) {
          if ($i=="pref"   && i+1<=NF) pref=$(i+1)
          if ($i=="handle" && i+1<=NF) handle=$(i+1)
          if ($i=="chain"  && i+1<=NF) chain=$(i+1)
          if ($i=="id"     && i+1<=NF) id=$(i+1)
          if ($i=="name"   && i+1<=NF) name=$(i+1)
        }
      }
      function maybe_print() {
        if (!printed && id!="") {
          printf "%-18s %-12s %-8s %-10s %-6s %-8s %s\n", dev, "tc/"dir, pref, handle, chain, id, name
          printed=1
        }
      }

      BEGIN { reset_block() }

      # New filter block
      /^filter/ {
        reset_block()
        try_parse_kv()
        maybe_print()     # handles "filter ... bpf ... id N ..." same-line format
        next
      }

      # Some iproute2 versions print a separate bpf line
      /^[[:space:]]*bpf/ {
        try_parse_kv()
        maybe_print()
        next
      }

      # Fallback: any line in the block containing " id N "
      /[[:space:]]id[[:space:]][0-9]+/ {
        try_parse_kv()
        maybe_print()
        next
      }
    '
  done
done
