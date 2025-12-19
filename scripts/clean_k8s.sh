#!/usr/bin/env bash
set -euo pipefail


sudo kubeadm reset -f
sudo systemctl stop kubelet
sudo systemctl disable kubelet

# Clean CNI state
sudo rm -rf /etc/cni/net.d
sudo rm -rf /var/lib/cni
sudo rm -rf /var/lib/kubelet
sudo rm -rf /var/lib/etcd  # only on control-plane if you’re sure
sudo rm -rf ~/.kube

# (Optional) flush iptables if this is a lab box
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -X

