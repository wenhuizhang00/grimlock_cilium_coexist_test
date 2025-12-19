#!/usr/bin/env bash
set -e

DEVS="enp94s0f0 cilium_host cilium_net cilium_vxlan lxc_health"

echo "=== bpftool net (overview) ==="
sudo bpftool net || echo "bpftool net not supported"

echo
for dev in $DEVS; do
  echo "=== dev: $dev ==="
  ip addr show $dev 2>/dev/null || { echo "  (no such dev)"; echo; continue; }
  echo "--- tc qdisc ---"
  sudo tc qdisc show dev $dev 2>/dev/null || echo "  (no qdisc)"
  echo "--- tc filters (ingress) ---"
  sudo tc filter show dev $dev ingress 2>/dev/null || echo "  (no ingress filter)"
  echo "--- tc filters (egress) ---"
  sudo tc filter show dev $dev egress 2>/dev/null || echo "  (no egress filter)"
  echo
done
