#!/usr/bin/env bash
set -euo pipefail

echo "=== [CHECK] Kubernetes & Cilium cleanup ==="

########################################
# 1. Kubernetes control-plane/runtime
########################################
echo
echo "==[1] Kubernetes components =="
if command -v kubeadm >/dev/null 2>&1; then
  echo "kubeadm binary: present"
else
  echo "kubeadm binary: NOT found"
fi

if command -v kubectl >/dev/null 2>&1; then
  echo "kubectl binary: present"
  echo "kubectl get nodes (may fail if cluster is gone):"
  kubectl get nodes 2>&1 || echo "  (kubectl cannot talk to apiserver: this usually means no active cluster here)"
else
  echo "kubectl binary: NOT found"
fi

echo
echo "Systemd services (kubelet):"
systemctl is-active kubelet 2>/dev/null || echo "  kubelet: not active (good if you intended to fully clean K8s)"

echo
echo "Kubernetes config dirs:"
for d in /etc/kubernetes /var/lib/kubelet /var/lib/etcd; do
  if [[ -d "$d" ]]; then
    echo "  $d : EXISTS"
  else
    echo "  $d : not present"
  fi
done

########################################
# 2. Cilium control-plane in cluster
########################################
echo
echo "==[2] Cilium in Kubernetes (cluster-side) =="

if command -v kubectl >/dev/null 2>&1; then
  echo "cilium pods in kube-system:"
  kubectl get pods -n kube-system -o wide | grep -E 'cilium|hubble' || echo "  no cilium/hubble pods found in kube-system"

  echo
  echo "Cilium DaemonSets:"
  kubectl get ds -A | grep -i cilium || echo "  no Cilium DaemonSets found"

  echo
  echo "Cilium CRDs:"
  kubectl get crd 2>/dev/null | grep cilium || echo "  no Cilium CRDs found"
else
  echo "kubectl missing, skipping cluster-side Cilium checks"
fi

########################################
# 3. Cilium on this node (datapath)
########################################
echo
echo "==[3] Cilium datapath on THIS NODE =="

echo "[3.1] Cilium-related interfaces:"
ip -o link show | grep -E 'cilium_|lxc' || echo "  no cilium_* or lxc* interfaces found"

echo
echo "[3.2] cilium_host / cilium_net explicitly:"
for dev in cilium_host cilium_net; do
  if ip link show "$dev" &>/dev/null; then
    echo "  $dev : PRESENT"
  else
    echo "  $dev : not present"
  fi
done

echo
echo "[3.3] bpftool net (tc hooks):"
if command -v bpftool >/dev/null 2>&1; then
  bpftool net 2>/dev/null || echo "  bpftool net failed"
else
  echo "  bpftool not installed"
fi

echo
echo "[3.4] tc qdisc with clsact:"
for dev in $(ip -o link show | awk -F': ' '{print $2}'); do
  Q=$(tc qdisc show dev "$dev" 2>/dev/null | grep clsact || true)
  if [[ -n "$Q" ]]; then
    echo "  $dev : $Q"
  fi
done
[[ -z "$(for dev in $(ip -o link show | awk -F': ' '{print $2}'); do tc qdisc show dev "$dev" 2>/dev/null | grep clsact || true; done)" ]] && \
  echo "  no clsact qdiscs found"

########################################
# 4. CNI config/binaries
########################################
echo
echo "==[4] CNI files =="
if [[ -d /etc/cni/net.d ]]; then
  echo "/etc/cni/net.d contents:"
  ls -1 /etc/cni/net.d
else
  echo "/etc/cni/net.d : not present"
fi

if [[ -d /opt/cni/bin ]]; then
  echo "/opt/cni/bin (Cilium-related):"
  ls -1 /opt/cni/bin | grep -i cilium || echo "  no Cilium CNI binaries present"
else
  echo "/opt/cni/bin : not present"
fi

########################################
# 5. BPF mount
########################################
echo
echo "==[5] BPF FS mounts =="
mount | grep -E '/sys/fs/bpf' || echo "  no /sys/fs/bpf mount found"

echo
echo "=== [SUMMARY HINTS] ==="
echo "- For *K8s fully cleaned on this node* you typically want:"
echo "    * kubelet inactive"
echo "    * /etc/kubernetes and /var/lib/kubelet gone (after 'kubeadm reset')"
echo "- For *Cilium fully cleaned* you want:"
echo "    * no cilium_* interfaces"
echo "    * no cilium CRDs or pods"
echo "    * no tc clsact hooks referencing cilium"
echo "    * no Cilium CNI configs/binaries in /etc/cni/net.d or /opt/cni/bin"
