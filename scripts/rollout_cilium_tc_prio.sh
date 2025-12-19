#!/usr/bin/env bash


# roll out a specific node for original 
# kubectl -n kube-system get pod -l k8s-app=cilium -o wide | grep ash1-as21-3-s3
# kubectl -n kube-system delete pod cilium-z9fls
# kubectl -n kube-system get pod -l k8s-app=cilium -o wide 

# roll out all
# kubectl -n kube-system rollout restart ds/cilium
# kubectl -n kube-system rollout status ds/cilium

#  operator roll out
# kubectl -n kube-system rollout restart deploy/cilium-operator
# kubectl -n kube-system rollout status deploy/cilium-operator

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  roll.sh <NEW_PRIO> [--prior ./prior.sh] [--dry-run] [--match REGEX] [--pin-dir DIR]

What it does:
  - Reads iface/hook/prio/handle/prog_id from prior.sh
  - For each Cilium-owned tc bpf program:
      pins the existing BPF prog (by prog_id) into bpffs
      attaches the pinned prog at NEW_PRIO (tc pref)
      deletes the old priority instance

Important fix:
  - Always operate on "protocol all" (and chain 0) to match Cilium-created filters.
  - Without protocol/chain, tc del/replace often won't match, leaving old prefs behind.

Examples:
  ./roll.sh 13
  ./roll.sh 13 --dry-run
  ./roll.sh 13 --pin-dir /sys/fs/bpf/tc-rollout
EOF
}

die() { echo "ERROR: $*" >&2; exit 1; }

NEW_PRIO="${1:-}"
shift || true
[[ -n "${NEW_PRIO}" ]] || { usage; exit 1; }
[[ "${NEW_PRIO}" =~ ^[0-9]+$ ]] || die "NEW_PRIO must be an integer"
(( NEW_PRIO >= 1 && NEW_PRIO <= 32767 )) || die "NEW_PRIO must be in [1..32767]"

PRIOR_SH="./prior.sh"
DRY_RUN="false"
MATCH_RE='^(cil|cilium|bpf_lxc)'
PIN_DIR="/sys/fs/bpf/tc-rollout"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prior) PRIOR_SH="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift 1 ;;
    --match) MATCH_RE="$2"; shift 2 ;;
    --pin-dir) PIN_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Must run as root (tc/bpftool needs CAP_NET_ADMIN)."
command -v tc >/dev/null || die "tc not found"
command -v bpftool >/dev/null || die "bpftool not found"
[[ -x "${PRIOR_SH}" ]] || die "prior.sh not found/executable: ${PRIOR_SH}"
[[ -d /sys/fs/bpf ]] || die "/sys/fs/bpf not mounted (bpffs required)"

run() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "+ $*"
  else
    eval "$@"
  fi
}

prog_name_by_id() {
  local id="$1"
  bpftool prog show id "${id}" 2>/dev/null | awk '
    NR==1 {
      for (i=1;i<=NF;i++) if ($i=="name") { print $(i+1); exit }
      exit
    }'
}

ensure_clsact() {
  local dev="$1"
  if ! tc qdisc show dev "${dev}" 2>/dev/null | grep -qE '\bclsact\b'; then
    run "tc qdisc add dev ${dev} clsact 2>/dev/null || true"
  fi
}

ensure_pin_dir() {
  run "mkdir -p ${PIN_DIR}"
}

pin_path_for() {
  local dev="$1" dir="$2" prog_id="$3" handle="$4"
  # stable pin name per dev/dir/handle/prog_id (not per old pref)
  echo "${PIN_DIR}/${dev}-${dir}-h${handle}-id${prog_id}"
}

pin_prog_if_needed() {
  local prog_id="$1" pin_path="$2"
  if bpftool prog show pinned "${pin_path}" >/dev/null 2>&1; then
    return 0
  fi
  run "bpftool prog pin id ${prog_id} ${pin_path}"
}

move_filter() {
  local dev="$1" dir="$2" old_pref="$3" handle="$4" prog_id="$5"

  if [[ "${old_pref}" == "${NEW_PRIO}" ]]; then
    echo "SKIP: ${dev} ${dir} prog_id=${prog_id} already at prio=${NEW_PRIO}"
    return 0
  fi

  ensure_clsact "${dev}"
  ensure_pin_dir

  local pin_path
  pin_path="$(pin_path_for "${dev}" "${dir}" "${prog_id}" "${handle#0x}")"

  echo "MOVE: ${dev} ${dir} prog_id=${prog_id} handle=${handle} ${old_pref} -> ${NEW_PRIO}"
  pin_prog_if_needed "${prog_id}" "${pin_path}"

  # IMPORTANT: match the actual Cilium filters: protocol all + chain 0
  run "tc filter replace dev ${dev} ${dir} protocol all pref ${NEW_PRIO} chain 0 handle ${handle} bpf da pinned ${pin_path}"

  # Delete the old instance (best-effort) - include protocol/chain/bpf so it matches
  run "tc filter del dev ${dev} ${dir} protocol all pref ${old_pref} chain 0 handle ${handle} bpf 2>/dev/null || true"
}

echo "==> Desired tc prio/pref: ${NEW_PRIO}"
echo "==> Using ${PRIOR_SH}"
echo "==> Matching bpftool prog name regex: ${MATCH_RE}"
echo "==> Pin dir: ${PIN_DIR}"
[[ "${DRY_RUN}" == "true" ]] && echo "==> DRY RUN (no changes will be applied)"

echo "==> Current hooks:"
"${PRIOR_SH}"

# Parse prior.sh output.
# Expected columns:
# IFACE HOOK PRIO HANDLE CHAIN PROG_ID PROG_NAME
mapfile -t LINES < <("${PRIOR_SH}" | awk 'NR>1 && NF>=6 {print $1,$2,$3,$4,$6}')

CHANGED=0
SKIPPED=0
TARGETED=0

for entry in "${LINES[@]}"; do
  read -r IFACE HOOK OLD_PRIO HANDLE PROG_ID <<<"${entry}"

  DIR=""
  case "${HOOK}" in
    tc/ingress) DIR="ingress" ;;
    tc/egress)  DIR="egress" ;;
    *) echo "SKIP: unknown hook format: ${HOOK}"; ((SKIPPED++)) || true; continue ;;
  esac

  PNAME="$(prog_name_by_id "${PROG_ID}" || true)"
  if [[ -z "${PNAME}" ]]; then
    echo "SKIP: ${IFACE} ${DIR} prog_id=${PROG_ID} (cannot resolve bpftool name)"
    ((SKIPPED++)) || true
    continue
  fi

  if ! [[ "${PNAME}" =~ ${MATCH_RE} ]]; then
    ((SKIPPED++)) || true
    continue
  fi

  ((TARGETED++)) || true

  if ! [[ "${HANDLE}" =~ ^0x[0-9a-fA-F]+$ ]]; then
    HANDLE="0x${HANDLE}"
  fi

  move_filter "${IFACE}" "${DIR}" "${OLD_PRIO}" "${HANDLE}" "${PROG_ID}"
  ((CHANGED++)) || true
done

echo "==> Summary: targeted=${TARGETED} changed_attempted=${CHANGED} skipped=${SKIPPED}"
echo "==> Resulting hooks:"
"${PRIOR_SH}"

