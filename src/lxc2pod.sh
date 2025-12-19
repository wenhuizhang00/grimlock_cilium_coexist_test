#!/usr/bin/env bash
set -euo pipefail

need(){ command -v "$1" >/dev/null || { echo "ERROR: missing $1" >&2; exit 1; }; }
need ip; need awk; need sed; need grep; need kubectl

# If running under sudo and KUBECONFIG isn't set, reuse invoking user's kubeconfig
if [[ -z "${KUBECONFIG:-}" && -n "${SUDO_USER:-}" && -f "/home/${SUDO_USER}/.kube/config" ]]; then
  export KUBECONFIG="/home/${SUDO_USER}/.kube/config"
fi

# Cache: podIP -> ns/pod
declare -A IP2POD
while read -r ns pod rest; do
  for ipaddr in $rest; do
    [[ -n "$ipaddr" ]] && IP2POD["$ipaddr"]="$ns/$pod"
  done
done < <(
  kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{" "}{range .status.podIPs[*]}{.ip}{" "}{end}{"\n"}{end}' \
    2>/dev/null || true
)

# Header
printf '%-16s %-42s %-60s %-16s %-40s %-40s %-17s\n' \
  "IF" "NETNS" "PODNAME" "IPV4" "IPV6" "LLA6(fe80)" "MAC"
printf '%-16s %-42s %-60s %-16s %-40s %-40s %-17s\n' \
  "----------------" "------------------------------------------" \
  "------------------------------------------------------------" \
  "----------------" "----------------------------------------" \
  "----------------------------------------" "-----------------"

ip -o link show \
  | awk -F': ' '$2 ~ /^lxc/ {print $2}' \
  | sed -E 's/@.*//; s/:$//' \
  | grep -v '^lxc_health$' \
  | while read -r IF; do
      [[ -n "$IF" ]] || continue

      # host-side link line for this iface
      line="$(ip -o link show "$IF" 2>/dev/null || true)"
      [[ -n "$line" ]] || continue

      # NETNS name (from link-netns ...)
      NETNS="$(echo "$line" | sed -n 's/.*link-netns \([^ ]*\).*/\1/p')"

      # host-side MAC
      MAC="$(echo "$line" | sed -n 's/.*link\/ether \([0-9a-f:]\{17\}\).*/\1/p')"
      [[ -n "${MAC:-}" ]] || MAC="-"

      # host-side fe80 (link-local) IPv6 on this lxc iface
      LLA6="$(ip -o -6 addr show dev "$IF" 2>/dev/null \
              | awk '$0 ~ / scope link / {print $4}' \
              | cut -d/ -f1 | head -n1 || true)"
      [[ -n "${LLA6:-}" ]] || LLA6="-"

      if [[ -z "${NETNS:-}" ]]; then
        printf '%-16s %-42s %-60s %-16s %-40s %-40s %-17s\n' \
          "$IF" "-" "UNMAPPED(no netns)" "-" "-" "$LLA6" "$MAC"
        continue
      fi

      # Collect IPs inside pod netns (need sudo)
      IPS="$(sudo ip netns exec "$NETNS" ip -o addr show 2>/dev/null \
              | awk '{print $4}' | cut -d/ -f1 || true)"

      IPV4="-"
      IPV6="-"
      PODNAME="UNMAPPED"

      for ipaddr in $IPS; do
        # skip loopback + link-local (we already printed host-side fe80 in LLA6)
        [[ "$ipaddr" == 127.* ]] && continue
        [[ "$ipaddr" == "::1" ]] && continue
        [[ "$ipaddr" == fe80:* ]] && continue

        if [[ "$ipaddr" == *:* ]]; then
          [[ "$IPV6" == "-" ]] && IPV6="$ipaddr"
        else
          [[ "$IPV4" == "-" ]] && IPV4="$ipaddr"
        fi

        if [[ "$PODNAME" == "UNMAPPED" && -n "${IP2POD[$ipaddr]:-}" ]]; then
          PODNAME="${IP2POD[$ipaddr]}"
        fi
      done

      printf '%-16s %-42s %-60s %-16s %-40s %-40s %-17s\n' \
        "$IF" "$NETNS" "$PODNAME" "$IPV4" "$IPV6" "$LLA6" "$MAC"
    done

