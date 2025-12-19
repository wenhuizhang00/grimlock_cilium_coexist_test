#!/usr/bin/env bash
set -euo pipefail

KUBECTL="${KUBECTL:-kubectl}"
JQ="${JQ:-jq}"
CRICTL="${CRICTL:-crictl}"

need() { command -v "$1" >/dev/null 2>&1; }

for cmd in "$KUBECTL" "$JQ" ip nsenter "$CRICTL" column; do
  if ! need "$cmd"; then
    echo "ERROR: missing dependency: $cmd" >&2
    exit 1
  fi
done

get_host_if_by_ifindex() {
  local idx="$1"
  ip -o link show 2>/dev/null \
    | awk -v i="$idx" -F': ' '$1==i {print $2}' \
    | cut -d'@' -f1
}

# Build node->InternalIP map once
declare -A NODEIP
while IFS=$'\t' read -r n ip4; do
  [[ -n "${n:-}" ]] && NODEIP["$n"]="$ip4"
done < <(
  "$KUBECTL" get nodes -o json \
  | "$JQ" -r '
      .items[]
      | .metadata.name as $n
      | (
          .status.addresses // []
          | map(select(.type=="InternalIP"))[0].address
        ) as $ip
      | [$n, ($ip // "N/A")] | @tsv
    '
)

{
  echo -e "NAMESPACE\tPOD\tNODE_IP\tPOD_IFACE\tHOST_IFACE\tPOD_IPV4\tPOD_IPV6"

  mapfile -t namespaces < <("$KUBECTL" get ns -o json | "$JQ" -r '.items[].metadata.name' | sort)

  for ns in "${namespaces[@]}"; do
    pods_json="$("$KUBECTL" get pods -n "$ns" -o json 2>/dev/null)" || continue
    pod_count="$("$JQ" -r '(.items // []) | length' <<<"$pods_json")"
    [[ "$pod_count" -eq 0 ]] && continue

    while IFS=$'\t' read -r pod nodeName pod_ipv4 pod_ipv6 cid; do
      [[ -z "${nodeName:-}" ]] && nodeName="N/A"
      node_ip="${NODEIP[$nodeName]:-N/A}"

      pod_iface="N/A"
      host_iface="N/A"

      cid="${cid#*://}"

      if [[ -n "$cid" ]]; then
        pid="$("$CRICTL" inspect "$cid" 2>/dev/null | "$JQ" -r '.info.pid // .pid // empty' || true)"
        if [[ -n "${pid:-}" && "$pid" != "0" ]]; then
          pod_iface="$(nsenter -t "$pid" -n sh -c \
            "ip -o link show | awk -F': ' '\$2!=\"lo\" {print \$2; exit}' | cut -d'@' -f1" \
            2>/dev/null || echo "N/A")"

          if [[ "$pod_iface" != "N/A" ]]; then
            host_ifindex="$(nsenter -t "$pid" -n sh -c "cat /sys/class/net/$pod_iface/iflink" 2>/dev/null || true)"
            if [[ -n "${host_ifindex:-}" ]]; then
              host_iface="$(get_host_if_by_ifindex "$host_ifindex")"
              [[ -z "${host_iface:-}" ]] && host_iface="ifindex:$host_ifindex"
            fi
          fi
        fi
      fi

      [[ -z "${pod_ipv4:-}" ]] && pod_ipv4="N/A"
      [[ -z "${pod_ipv6:-}" ]] && pod_ipv6="N/A"

      echo -e "${ns}\t${pod}\t${node_ip}\t${pod_iface}\t${host_iface}\t${pod_ipv4}\t${pod_ipv6}"
    done < <(
      "$JQ" -r '
        .items[]
        | .metadata.name as $pod
        | (.spec.nodeName // "N/A") as $node
        | (
            ([.status.podIPs[]?.ip] + (if .status.podIP then [.status.podIP] else [] end))
            | unique
          ) as $ips
        | (
            ($ips | map(select(index(":")==null)) | .[0]) // ""
          ) as $ipv4
        | (
            ($ips | map(select(index(":")!=null)) | .[0]) // ""
          ) as $ipv6
        | ((.status.containerStatuses // [])[0].containerID // "") as $cid
        | [$pod, $node, $ipv4, $ipv6, $cid] | @tsv
      ' <<<"$pods_json"
    )
  done
} | column -t -s $'\t'

