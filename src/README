# Cilium + TC Flow Log Workflow (kube_scan → node login → cleanup/rollout → lxc2pod → build → hook → trace → cleanup)

This README describes the end-to-end workflow to:
1) locate where a **target service** is running,
2) log into the **right node(s)**,
3) ensure the node is in a **clean state**,
4) **roll out / restart Cilium** (optionally downgrade to a prior version),
5) map **service pods → node interfaces (lxc*)**,
6) compile & **hook a tc BPF program** onto those interfaces,
7) read **data flow** from tracing output,
8) clean up after testing.

---

## Prereqs

- You have `kubectl` access to the cluster.
- On the node(s), you have:
  - `sudo`, `ip`, `tc` available
  - `clang` + kernel headers for BPF build (or build elsewhere and copy `.o`)
  - access to `/sys/kernel/debug/tracing/trace_pipe`
- Scripts assumed in this repo:
  - `kube_scan.sh` (find pods for a service + which node)
  - `prior.sh` (health/status check)
  - `clean.sh` (remove tc hooks / reset state)
  - `rollout_cilium.sh` (restart cilium on node or cluster; optionally set version/prior)
  - `lxc2pod2.sh` (map lxc interface → netns → pod → IPs (+ optional MAC/link-local))
  - `Makefile` (build `tc_flow_log.bpf.o`)
  - `lxc_hook_and_map.sh` (hook `.o` to interfaces + write prog_id map TSV)
  - `trace_reader.py` (parse trace_pipe → iface/prog/dir/src/dst/ports)

---

## Step 1: kube_scan — find which node the target service runs on

Goal: identify the **node(s)** that run the target workload pods.

### Example: find pods behind a service
Common approaches:
- by service selector labels
- by deployment name
- by `kubectl get pods -A -o wide | grep <keyword>`

Run:
```bash
./kube_scan.sh
```

## Step 2: log on to the target node

SSH to the node(s) you found in step 1


run prior.sh status check

Goal: confirm the node is “clean enough” for the experiment.

```
sudo ./prior.sh

```

## Step 3: clean if needed (remove prior hooks/state)

```
sudo ./clean.sh

sudo ./prior.sh
```

## Step 4: roll out / restart Cilium 

(optionally with a prior version)

```
sudo ./rollout_cilium.sh --node ash1-as21-3-s3

sudo ./rollout_cilium.sh --all
```
you can change the prior here


## Step 5: find service pods → lxc interfaces with lxc2pod

Goal: identify the interfaces and netns hosting your target service containers on this node.

```
sudo ./lxc2pod2.sh

```

It should output a table like:

- IF (lxc*)

- NETNS (cni-*)

- PODNAME (ns/pod)

- IPV4 / IPV6

- (optional) link-local IPv6 + MAC


## Step 6: compile the tc BPF program

Assuming you have tc_flow_log.bpf.c and a Makefile:


hook the program onto the target interfaces

Goal: attach BPF to both ingress + egress on the selected lxc* interfaces.

```
make
ls -l tc_flow_log.bpf.o


ONLY_IFACES="lxc9f92a81db4da lxcb315c7e6e5a0" \
  sudo -E ./lxc_hook_and_map.sh tc_flow_log.bpf.o /tmp/lxc_tc_prog_map.tsv

```




## Step 7: Read

run traffic tests

Generate the traffic you care about (client → service, service → upstream, etc.).
Do your normal test procedure here.

read flow logs from trace_pipe using Python

Goal: parse the bpf_printk key/value lines and reconstruct flow tuples:

interface (from ifindex → ifname)

prog_id (via mapping TSV)

direction (ingress/egress)

src IP:port

dst IP:port


```
sudo python3 trace_reader.py \
  --trace /sys/kernel/debug/tracing/trace_pipe \
  --map /tmp/lxc_tc_prog_map.tsv

```

## Step 8: Clean

```
sudo ./clean.sh
sudo ./prior.sh

```

