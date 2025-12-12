#!/usr/bin/env bash
set -euo pipefail

########################################################################
# Bare Metal K8s (Kubeadm) Installation & Cilium Deployment Script
#
# This script:
#   - Prepares the system (swap, sysctl, modules)
#   - Installs containerd
#   - Installs kubeadm/kubelet/kubectl
#   - Initializes a single control-plane cluster with kubeadm
#   - Installs Cilium as CNI
#   - Runs a simple connectivity test
#
# Target OS: Ubuntu/Debian
# Run as: root (sudo -i; then ./setup-k8s-cilium.sh)
########################################################################

### --- User-tunable variables -----------------------------------------

K8S_VERSION_REPO="v1.30"                 # Kubernetes stable version line for pkgs.k8s.io
POD_NETWORK_CIDR="10.244.0.0/16"         # Pod CIDR for kubeadm init
CILIUM_CLI_URL="https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz"

TEST_NAMESPACE="test"
TEST_DEPLOY_NAME="echo"
TEST_IMAGE="nginxdemos/hello"
TEST_CURL_POD="curl"
TEST_CURL_IMAGE="curlimages/curl"

# If you want to skip some phases, set these to "false"
DO_PREPARE_SYSTEM="true"
DO_INSTALL_CONTAINERD="true"
DO_INSTALL_K8S="true"
DO_KUBEADM_INIT="true"
DO_INSTALL_CILIUM="true"
DO_RUN_CONNECTIVITY_TEST="true"

########################################################################
# Helpers
########################################################################

must_be_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root. Use: sudo -i; then run it again."
    exit 1
  fi
}

run_or_warn() {
  # Helper that doesn't exit on failure (for optional steps)
  local cmd="$*"
  echo "+ $cmd"
  if ! eval "$cmd"; then
    echo "WARNING: Command failed (continuing): $cmd"
  fi
}

########################################################################
# I. System Preparation
########################################################################

disable_swap() {
  echo "==> Disabling swap (temporary and permanent)..."

  # Temporarily disable swap
  swapoff -a || true

  # Permanently disable: comment out swap entries in /etc/fstab
  if [[ -f /etc/fstab ]]; then
    sed -i.bak '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab || true
  fi
}

configure_kernel_params() {
  echo "==> Configuring kernel params (br_netfilter, ip_forward)..."

  cat <<EOF >/etc/modules-load.d/k8s.conf
br_netfilter
EOF

  modprobe br_netfilter || true

  cat <<EOF >/etc/sysctl.d/99-k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

  sysctl --system
}

########################################################################
# II. Install Container Runtime (containerd)
########################################################################

install_containerd() {
  echo "==> Installing containerd..."

  apt-get update
  apt-get install -y containerd

  mkdir -p /etc/containerd
  containerd config default >/etc/containerd/config.toml

  # Change SystemdCgroup = true
  sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml

  systemctl restart containerd
  systemctl enable containerd
}

########################################################################
# III. Install Kubernetes Components (kubeadm/kubelet/kubectl)
########################################################################

install_k8s_binaries() {
  echo "==> Installing kubeadm, kubelet, kubectl from pkgs.k8s.io (${K8S_VERSION_REPO})..."

  apt-get update
  apt-get install -y apt-transport-https ca-certificates curl gpg

  mkdir -p /etc/apt/keyrings

  curl -fsSL "https://pkgs.k8s.io/core:/stable:/${K8S_VERSION_REPO}/deb/Release.key" \
    | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

  cat <<EOF >/etc/apt/sources.list.d/kubernetes.list
deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_VERSION_REPO}/deb/ /
EOF

  apt-get update
  apt-get install -y kubelet kubeadm kubectl
  systemctl enable kubelet
}

########################################################################
# IV. kubeadm init (Control Plane)
########################################################################

kubeadm_init() {
  echo "==> Running kubeadm init (control-plane)..."

  # Only run if not yet initialized
  if [[ -f /etc/kubernetes/admin.conf ]]; then
    echo "kubeadm already initialized (/etc/kubernetes/admin.conf exists); skipping kubeadm init."
  else
    kubeadm init --pod-network-cidr="${POD_NETWORK_CIDR}"
  fi

  echo "==> Setting up kubeconfig for current user (/root/.kube)..."

  local kube_home="${HOME}"
  mkdir -p "${kube_home}/.kube"
  cp -i /etc/kubernetes/admin.conf "${kube_home}/.kube/config"
  chown "$(id -u):$(id -g)" "${kube_home}/.kube/config"

  echo "==> Checking node status (should be NotReady until CNI is installed)..."
  kubectl get nodes -o wide || true
}

########################################################################
# V. Deploy Cilium (CNI)
########################################################################

install_cilium() {
  echo "==> Installing Cilium CLI..."
  cd /tmp

  curl -L --remote-name-all "${CILIUM_CLI_URL}"
  tar xzvf cilium-linux-amd64.tar.gz
  mv cilium /usr/local/bin/
  chmod +x /usr/local/bin/cilium

  echo "==> Cilium CLI version:"
  cilium version || true

  export KUBECONFIG="${HOME}/.kube/config"

  echo "==> Installing Cilium CNI into the cluster..."
  cilium install

  echo "==> Cilium status:"
  cilium status

  echo "==> kube-system pods (Cilium DaemonSet etc.):"
  kubectl get pods -n kube-system -o wide
}

########################################################################
# VI. Connectivity Test
########################################################################

run_connectivity_test() {
  echo "==> Running basic connectivity test with nginx echo service..."

  kubectl create ns "${TEST_NAMESPACE}" >/dev/null 2>&1 || true

  # 2. Deploy echo service (nginxdemos/hello)
  kubectl -n "${TEST_NAMESPACE}" create deployment "${TEST_DEPLOY_NAME}" \
    --image="${TEST_IMAGE}" >/dev/null 2>&1 || true

  # Wait a bit for pod to be created
  echo "   Waiting 10s for deployment to come up..."
  sleep 10

  # 3. Expose service (ClusterIP)
  kubectl -n "${TEST_NAMESPACE}" expose deployment "${TEST_DEPLOY_NAME}" \
    --port 80 --type ClusterIP >/dev/null 2>&1 || true

  echo "   Current services in namespace ${TEST_NAMESPACE}:"
  kubectl -n "${TEST_NAMESPACE}" get svc

  # 4. Launch curl pod to test access
  echo "   Launching curl pod to test echo service..."
  kubectl -n "${TEST_NAMESPACE}" run "${TEST_CURL_POD}" \
    --image="${TEST_CURL_IMAGE}" --restart=Never --command -- \
    sh -c "sleep 5; curl -s ${TEST_DEPLOY_NAME}.${TEST_NAMESPACE}.svc.cluster.local" || true

  echo
  echo "You can manually inspect the curl pod output with:"
  echo "  kubectl -n ${TEST_NAMESPACE} logs ${TEST_CURL_POD}"
}

########################################################################
# VII. Check BPF hooks (optional)
########################################################################

check_bpf() {
  echo "==> Checking BPF network hooks (bpftool net)..."
  if command -v bpftool >/dev/null 2>&1; then
    bpftool net || true
  else
    echo "bpftool not installed. Install with: apt-get install -y bpftool"
  fi
}

########################################################################
# Main
########################################################################

main() {
  must_be_root

  echo "===== Bare Metal K8s + Cilium Setup Script ====="

  if [[ "${DO_PREPARE_SYSTEM}" == "true" ]]; then
    disable_swap
    configure_kernel_params
  else
    echo "Skipping system preparation (DO_PREPARE_SYSTEM=false)"
  fi

  if [[ "${DO_INSTALL_CONTAINERD}" == "true" ]]; then
    install_containerd
  else
    echo "Skipping containerd installation (DO_INSTALL_CONTAINERD=false)"
  fi

  if [[ "${DO_INSTALL_K8S}" == "true" ]]; then
    install_k8s_binaries
  else
    echo "Skipping kubeadm/kubelet/kubectl install (DO_INSTALL_K8S=false)"
  fi

  if [[ "${DO_KUBEADM_INIT}" == "true" ]]; then
    kubeadm_init
  else
    echo "Skipping kubeadm init (DO_KUBEADM_INIT=false)"
  fi

  if [[ "${DO_INSTALL_CILIUM}" == "true" ]]; then
    install_cilium
  else
    echo "Skipping Cilium install (DO_INSTALL_CILIUM=false)"
  fi

  if [[ "${DO_RUN_CONNECTIVITY_TEST}" == "true" ]]; then
    run_connectivity_test
  else
    echo "Skipping connectivity test (DO_RUN_CONNECTIVITY_TEST=false)"
  fi

  check_bpf

  echo
  echo "===== DONE ====="
  echo "Cluster should be up with Cilium as CNI."
  echo "Useful commands:"
  echo "  kubectl get nodes -o wide"
  echo "  kubectl get pods -A -o wide"
  echo "  bpftool net"
}

main "$@"
