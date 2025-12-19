#!/usr/bin/env bash
#
# clean_cilium.sh
# Best-effort script to remove Cilium from a Kubernetes cluster
# and clean local node datapath state (CNI config, tc BPF, cilium_* interfaces).
#
# Run as root (or via sudo). Networking for pods will break until another CNI is installed.

set -euo pipefail

echo "=== [CILIUM CLEANUP] WARNING ==="
echo "This will:
  - Uninstall Cilium from the cluster (if possible)
  - Delete Cilium CRDs and kube resources
  - Remove Cilium CNI config and binaries
  - Remove Cilium tc/BPF hooks and cilium_* interfaces on THIS NODE.
Pod networking will be broken until another CNI is installed.
"
sleep 2

#######################################
# 1. Cluster-side uninstall
#######################################
echo "=== [1] Cluster-side uninstall ==="

# 1.1 Try cilium CLI uninstall (if available)
if command -v cilium >/dev/null 2>&1; then
  echo "[1.1] Found cilium CLI -> running 'cilium uninstall'..."
  cilium uninstall || echo "  (cilium uninstall failed or not applicable, continuing...)"
else
  echo "[1.1] cilium CLI not found, skipping cilium uninstall"
fi

# 1.2 Best-effort kubectl clean-up (DaemonSets/Deployments/etc.)
echo "[1.2] Deleting Cilium DaemonSets/Deployments/Services/ConfigMaps in kube-system..."

kubectl delete daemonset,deploy,svc,cm,secret \
  -n kube-system \
  -l k8s-app=cilium \
  --ignore-not-found=true || true

# cilium-operator (some installs just use app=cilium-operator)
kubectl delete deploy \
  -n kube-system \
  -l app=cilium-operator \
  --ignore-not-found=true || true

# Some installs use 'cilium' namespace too
echo "[1.3] Deleting cilium namespace (if exists)..."
kubectl delete namespace cilium --ignore-not-found=true || true

# 1.4 Delete Cilium CRDs
echo "[1.4] Deleting Cilium CRDs (if any)..."
CILIUM_CRDS=$(kubectl get crd 2>/dev/null | awk '/cilium/ {print $1}' || true)
if [[ -n "${CILIUM_CRDS}" ]]; then
  echo "  Found CRDs:"
  echo "${CILIUM_CRDS}" | sed 's/^/    - /'
  echo "  Deleting..."
  echo "${CILIUM_CRDS}" | xargs kubectl delete crd || true
else
  echo "  No Cilium CRDs found (or kubectl not working)"
fi

#######################################
# 2. Remove CNI config & binaries (this node)
#######################################
echo "=== [2] Removing Cilium CNI config & binaries on THIS NODE ==="

# 2.1 CNI config
if [[ -d /etc/cni/net.d ]]; then
  echo "[2.1] Removing Cilium CNI configs under /etc/cni/net.d..."
  sudo rm -f /etc/cni/net.d/*cilium*.conf /etc/cni/net.d/*cilium*.conflist 2>/dev/null || true
else
  echo "[2.1] /etc/cni/net.d does not exist, skipping"
fi

# 2.2 CNI plugin binaries
if [[ -d /opt/cni/bin ]]; then
  echo "[2.2] Removing Cilium CNI binaries from /opt/cni/bin..."
  sudo rm -f /opt/cni/bin/cilium-cni /opt/cni/bin/cilium 2>/dev/null || true
else
  echo "[2.2] /opt/cni/bin does not exist, skipping"
fi

#######################################
# 3. Clean tc/BPF and Cilium interfaces (this node)
#######################################
echo "=== [3] Cleaning tc/BPF and Cilium interfaces on THIS NODE ==="

# 3.1 Remove tc clsact qdiscs from interfaces with Cilium tc programs
if command -v bpftool >/dev/null 2>&1; then
  echo "[3.1] Removing tc clsact qdiscs on interfaces with Cilium tc hooks..."
  DEVS=$(sudo bpftool net 2>/dev/null | awk '/clsact/ {print $1}' | sed 's/(.*//' | sort -u || true)
  if [[ -n "${DEVS}" ]]; then
    echo "  Interfaces with tc BPF:"
    echo "${DEVS}" | sed 's/^/    - /'
    echo "${DEVS}" | while read -r dev; do
      if [[ -n "${dev}" ]]; then
        echo "  -> tc qdisc del dev ${dev} clsact"
        sudo tc qdisc del dev "${dev}" 2>/dev/null || true
      fi
    done
  else
    echo "  No interfaces with tc clsact found via bpftool net"
  fi
else
  echo "[3.1] bpftool not found, skipping tc/BPF auto-clean via bpftool"
fi

# 3.2 Extra: try removing clsact from cilium_* and lxc* explicitly
echo "[3.2] Extra tc cleanup on cilium_* and lxc* interfaces..."
for dev in $(ip -o link show | awk -F': ' '{print $2}' | grep -E '^cilium_|^lxc' || true); do
  echo "  -> tc qdisc del dev ${dev} clsact"
  sudo tc qdisc del dev "${dev}" 2>/dev/null || true
done

# 3.3 Delete cilium_* interfaces, including cilium_host and cilium_net
echo "[3.3] Deleting cilium_* interfaces (including cilium_host / cilium_net)..."

# Generic: any interface starting with cilium_
for dev in $(ip -o link show | awk -F': ' '{print $2}' | grep '^cilium_' || true); do
  echo "  -> ip link del ${dev}"
  sudo ip link del "${dev}" 2>/dev/null || true
done

# Extra safety: explicitly try cilium_host and cilium_net
for dev in cilium_host cilium_net; do
  if ip link show "$dev" &>/dev/null; then
    echo "  -> explicitly deleting ${dev}"
    sudo ip link del "$dev" 2>/dev/null || true
  fi
done

echo "[3.4] lxc* interfaces are tied to pods and usually disappear when pods are removed."

#######################################
# 4. BPF filesystem mounts (optional)
#######################################
echo "=== [4] Optional: check BPF mounts for Cilium ==="
if mount | grep -q "/sys/fs/bpf"; then
  CILIUM_BPF_MOUNT=$(mount | awk '/bpf/ && /cilium/ {print $3}' || true)
  if [[ -n "${CILIUM_BPF_MOUNT}" ]]; then
    echo "  Found Cilium BPF mount at ${CILIUM_BPF_MOUNT}, trying to umount..."
    sudo umount "${CILIUM_BPF_MOUNT}" 2>/dev/null || true
  else
    echo "  No dedicated /sys/fs/bpf/cilium mount found; skipping umount."
  fi
else
  echo "  No /sys/fs/bpf mount found in 'mount' output."
fi

echo
echo "=== [DONE] Cilium cleanup on THIS NODE complete. ==="
echo "Run this on every node that had Cilium, then install a new CNI if you want pod networking again."
