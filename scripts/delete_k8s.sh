#!/usr/bin/env bash
set -euo pipefail


sudo kubeadm reset -f
sudo systemctl stop kubelet
sudo systemctl disable kubelet
sudo rm -rf /etc/cni/net.d /var/lib/cni /var/lib/kubelet ~/.kube
