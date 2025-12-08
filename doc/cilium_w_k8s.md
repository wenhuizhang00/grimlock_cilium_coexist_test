# Bare Metal K8s (Kubeadm) Installation & Cilium Deployment Guide

This document outlines the steps to natively install a Kubernetes cluster on physical machines (Ubuntu/Debian) using `kubeadm` and deploy Cilium as the CNI network plugin.

## I. System Preparation

Perform these steps on **all nodes** (Control Plane and Workers).

### 1.1 Disable Swap
Kubernetes requires swap to be disabled to function correctly.

```bash
# Temporarily disable
sudo swapoff -a

# Permanently disable: Comment out the swap line in /etc/fstab
sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
```

### 1.2 Configure Kernel Parameters
Load the br_netfilter module and adjust network forwarding parameters.
```
# Load modules
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
br_netfilter
EOF

sudo modprobe br_netfilter

# Set system parameters
cat <<EOF | sudo tee /etc/sysctl.d/99-k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

# Apply parameters
sudo sysctl --system
```

## II. Install Container Runtime (Containerd)
We recommend using containerd as the runtime.
```
sudo apt-get update
sudo apt-get install -y containerd

sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml > /dev/null

# Change SystemdCgroup from false to true
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml

# Restart and enable on boot
sudo systemctl restart containerd
sudo systemctl enable containerd
```


## III. Install Kubernetes Components

Use the official new repository (pkgs.k8s.io) to install kubelet, kubeadm, and kubectl.

```
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gpg

# Create keyring directory
sudo mkdir -p /etc/apt/keyrings

# Download GPG key (Using v1.30 as an example, adjust as needed)
curl -fsSL [https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key](https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key) \
  | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

# Add the apt source
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] \
[https://pkgs.k8s.io/core:/stable:/v1.30/deb/](https://pkgs.k8s.io/core:/stable:/v1.30/deb/) /" \
  | sudo tee /etc/apt/sources.list.d/kubernetes.list


sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo systemctl enable kubelet


# Run kubeadm init
sudo kubeadm init --pod-network-cidr=10.244.0.0/16

# Configure Kubeconfig
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

# Verify Node Status, The node status should be NotReady at this stage because no CNI is installed yet.
kubectl get nodes



```

## V. Deploy Cilium (Native CNI)

```
curl -L --remote-name-all [https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz](https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz)
tar xzvf cilium-linux-amd64.tar.gz
sudo mv cilium /usr/local/bin/

# Verify version
cilium version

export KUBECONFIG=$HOME/.kube/config

# Auto-detect settings and install
cilium install

# Check Cilium status
cilium status

# Check Pod execution (Cilium runs as a DaemonSet)
kubectl get pods -n kube-system -o wide
```

## VI. Connectivity Test
```
# 1. Create a test namespace
kubectl create ns test

# 2. Deploy an Nginx service
kubectl -n test create deployment echo --image=nginxdemos/hello

# 3. Expose the service (ClusterIP)
kubectl -n test expose deployment echo --port 80 --type ClusterIP

# 4. Launch a curl pod to test access
kubectl -n test run curl --image=curlimages/curl --restart=Never -it -- \
  curl -s echo.test.svc.cluster.local
```

## Check Node
```

sudo bpftool net
```

Topoloy 
```
        [ Pod1 (10.244.x.x) ]        [ Pod2 (10.244.y.y) ]
             eth0                          eth0
              |                              |
        [ veth in Pod ns ]            [ veth in Pod ns ]
              |                              |
        [ lxc514c... ]  [ lxc73bb... ]  [ lxc_health ]
              |                |              |
              |   (cil_from_container-*)      |
              +--------------+---------------+
                             |
                     [ cilium_host 10.0.0.231/32 ]
                   ingress: cil_to_host-cilium_host
                   egress : cil_from_host-cilium_host
                             |
                  [ cilium_net / cilium_vxlan ]
            ingress/egress: cil_to/from_overlay / to_host
                             |
                        [ enp94s0f0 ]
                   ingress: cil_from_netdev-enp94s0f0
                             |
                        Other Node

```






















