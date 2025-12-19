#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, List

TRACE_PIPE_DEFAULT = "/sys/kernel/debug/tracing/trace_pipe"

RE_KV = re.compile(r"bpf_trace_printk:\s*([A-Z][0-9A-Z]?)=([0-9a-fA-F]{16})")
RE_TS = re.compile(r"\]\s+\S+\s+([0-9]+\.[0-9]+):")  # timestamp before ": bpf_trace_printk"

PROTO_NAMES = {
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
    1: "ICMP",
}

def run_cmd(cmd: List[str], timeout: float = 2.0) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)

def ifindex_to_name(ifindex: int) -> str:
    try:
        return socket.if_indextoname(ifindex)
    except Exception:
        return f"if{ifindex}"

def u32_from_low(hex16: str) -> int:
    # low 32 bits are the last 8 hex chars
    return int(hex16[-8:], 16)

def cookie_from_high(hex16: str) -> str:
    # upper 32 bits are first 8 hex chars (used to correlate lines)
    return hex16[:8].lower()

def ipv4_from_u32_le(u32: int) -> str:
    b = u32.to_bytes(4, byteorder="little", signed=False)
    return str(ipaddress.IPv4Address(b))

def ipv6_from_parts_le(parts: List[int]) -> str:
    # parts: four u32, each little-endian chunk
    b = b"".join(p.to_bytes(4, byteorder="little", signed=False) for p in parts)
    return str(ipaddress.IPv6Address(b))

def dir_from_r(r: int) -> str:
    if r == 1:
        return "ingress"
    if r == 2:
        return "egress"
    return f"R={r}"

@dataclass
class PacketState:
    last_ts: float = 0.0
    ifindex: Optional[int] = None
    direction_r: Optional[int] = None
    proto: Optional[int] = None
    sport: Optional[int] = None
    dport: Optional[int] = None

    s4: Optional[int] = None
    d4: Optional[int] = None
    s6_parts: Dict[int, int] = field(default_factory=dict)  # S0..S3
    d6_parts: Dict[int, int] = field(default_factory=dict)  # D0..D3

    def ready(self) -> bool:
        if self.ifindex is None or self.direction_r is None or self.proto is None:
            return False
        # For L4 info, ports may be absent for ICMP/ICMPv6 traces; allow missing ports -> 0
        # Need at least one IP family:
        has_v4 = self.s4 is not None and self.d4 is not None
        has_v6 = all(k in self.s6_parts for k in (0,1,2,3)) and all(k in self.d6_parts for k in (0,1,2,3))
        return has_v4 or has_v6

    def src_dst(self) -> Tuple[str, str]:
        # prefer v4 if present
        if self.s4 is not None and self.d4 is not None:
            return ipv4_from_u32_le(self.s4), ipv4_from_u32_le(self.d4)
        # else v6
        s_parts = [self.s6_parts[i] for i in (0,1,2,3)]
        d_parts = [self.d6_parts[i] for i in (0,1,2,3)]
        return ipv6_from_parts_le(s_parts), ipv6_from_parts_le(d_parts)

class ProgLookup:
    """
    Best-effort mapping: (ifname, direction) -> prog_id (string).
    Tries bpftool net -j first; otherwise parses tc filter show output.
    """
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.cache: Dict[Tuple[str, str], str] = {}
        self.bpftool_ok = False
        if enabled:
            self._prime_bpftool_cache()

    def _prime_bpftool_cache(self):
        rc, out, _ = run_cmd(["bpftool", "-j", "net"], timeout=3.0)
        if rc != 0 or not out.strip():
            return
        try:
            data = json.loads(out)
        except Exception:
            return

        # bpftool net JSON varies by version; try a few common layouts.
        # We look for entries that mention "tc" and include ifname + direction + prog_id/id.
        def walk(x):
            if isinstance(x, dict):
                yield x
                for v in x.values():
                    yield from walk(v)
            elif isinstance(x, list):
                for v in x:
                    yield from walk(v)

        for obj in walk(data):
            # heuristics
            ifname = obj.get("ifname") or obj.get("dev") or obj.get("device")
            hook = obj.get("attach_type") or obj.get("hook") or obj.get("direction")
            prog_id = obj.get("id") or obj.get("prog_id") or obj.get("progId")

            if ifname and hook and prog_id:
                hk = str(hook).lower()
                if "ingress" in hk:
                    self.cache[(ifname, "ingress")] = str(prog_id)
                elif "egress" in hk:
                    self.cache[(ifname, "egress")] = str(prog_id)

        if self.cache:
            self.bpftool_ok = True

    def _tc_lookup(self, ifname: str, direction: str) -> Optional[str]:
        # direction: ingress/egress
        rc, out, _ = run_cmd(["tc", "filter", "show", "dev", ifname, direction], timeout=2.0)
        if rc != 0:
            return None
        # Try to find "id N" in tc output (often present for bpf filters)
        m = re.search(r"\bid\s+([0-9]+)\b", out)
        if m:
            return m.group(1)
        return None

    def get(self, ifname: str, direction: str) -> str:
        if not self.enabled:
            return "-"
        key = (ifname, direction)
        if key in self.cache:
            return self.cache[key]
        # fallback to tc
        pid = self._tc_lookup(ifname, direction)
        if pid:
            self.cache[key] = pid
            return pid
        return "-"

def parse_trace_pipe(path: str, no_prog_lookup: bool, idle_timeout: float):
    prog = ProgLookup(enabled=not no_prog_lookup)
    states: Dict[str, PacketState] = {}

    def maybe_emit(cookie: str):
        st = states.get(cookie)
        if not st or not st.ready():
            return
        ifname = ifindex_to_name(st.ifindex or -1)
        direction = dir_from_r(st.direction_r or -1)
        prog_id = prog.get(ifname, direction)
        src_ip, dst_ip = st.src_dst()
        sport = st.sport or 0
        dport = st.dport or 0
        proto = st.proto or 0
        # output: iface prog_id ingress/egress src ip port dst ip port
        print(f"{ifname}({st.ifindex}) {prog_id} {direction} {src_ip}:{sport} --> {dst_ip}:{dport} proto={proto}({PROTO_NAMES.get(proto,'')})")
        sys.stdout.flush()
        states.pop(cookie, None)

    def cleanup(now_ts: float):
        # drop partial states not updated recently
        dead = [k for k, v in states.items() if v.last_ts and (now_ts - v.last_ts) > idle_timeout]
        for k in dead:
            states.pop(k, None)

    # Open as a streaming file
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = RE_KV.search(line)
            if not m:
                continue
            key, hex16 = m.group(1), m.group(2)
            cookie = cookie_from_high(hex16)
            val = u32_from_low(hex16)

            ts = 0.0
            mt = RE_TS.search(line)
            if mt:
                try:
                    ts = float(mt.group(1))
                except Exception:
                    ts = 0.0

            st = states.get(cookie)
            if st is None:
                st = PacketState()
                states[cookie] = st
            if ts:
                st.last_ts = ts

            # Fill fields
            if key == "I":
                st.ifindex = val
            elif key == "R":
                st.direction_r = val
            elif key == "P":
                st.proto = val
            elif key == "SP":
                st.sport = val & 0xFFFF
            elif key == "DP":
                st.dport = val & 0xFFFF
            elif key == "S4":
                st.s4 = val
            elif key == "D4":
                st.d4 = val
            elif key.startswith("S") and len(key) == 2 and key[1].isdigit():
                idx = int(key[1])
                if 0 <= idx <= 3:
                    st.s6_parts[idx] = val
            elif key.startswith("D") and len(key) == 2 and key[1].isdigit():
                idx = int(key[1])
                if 0 <= idx <= 3:
                    st.d6_parts[idx] = val

            maybe_emit(cookie)
            if ts:
                cleanup(ts)

def main():
    ap = argparse.ArgumentParser(description="Parse /sys/kernel/debug/tracing/trace_pipe bpf_trace_printk records into iface/prog/dir/5-tuple.")
    ap.add_argument("--path", default=TRACE_PIPE_DEFAULT, help=f"trace_pipe path (default: {TRACE_PIPE_DEFAULT})")
    ap.add_argument("--no-prog-lookup", action="store_true", help="Do not try to look up tc/bpf prog id (prints '-')")
    ap.add_argument("--idle-timeout", type=float, default=3.0, help="Seconds of inactivity to drop incomplete packet groups (default: 3.0)")
    args = ap.parse_args()

    if not os.path.exists(args.path):
        print(f"ERROR: path not found: {args.path}", file=sys.stderr)
        sys.exit(2)

    parse_trace_pipe(args.path, args.no_prog_lookup, args.idle_timeout)

if __name__ == "__main__":
    main()

