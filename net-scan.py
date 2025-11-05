"""
Network Scanner CLI

Features:
- Auto subnet detection (best-effort; pass --cidr to be explicit)
- Methods: ARP (fast, requires scapy & admin), PING (portable)
- Optional reverse DNS lookups
- Outputs table, and optional JSON/CSV files

Usage examples:
  python net_scan.py                 # auto detect + auto method
  python net_scan.py --cidr 192.168.1.0/24 --method ping --rdns
  python net_scan.py --json hosts.json --csv hosts.csv
"""
from __future__ import annotations
import argparse
import asyncio
import csv
import ipaddress
import json
import os
import platform
import re 
import shlex
import socket
import subprocess
import sys 
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional, Tuple, Dict

@dataclass
class Host:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    method: str = "" #arp or ping

def _is_root() -> bool:
    if os.name == "nt":
     # Heuristic: net session requires admin; avoid extra prompt
      try:
        subprocess.run(["net", "session"], capture_output=True, text=True, check=False)
        # On non-admin returns non-zero; we just detect we can run it
        return True # Windows detection is flaky; don't block ARP, scapy will error if not admin
      except Exception:
        return False 
    else:
       return os.geteuid() == 0
    
def _which(cmd: str) -> Optional[str]:
    from shutil import which
    return which(cmd)

def _run(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

def _netmask_to_cidr(mask: str) -> Optional[int]:
    try:
        parts = [int(p) for p in mask.split(".")]
        bits = "".join(f"{p:08b}" for p in parts)
        if "01" in bits:  # invalid non-contiguous mask
            return None
        return bits.count("1")
    except Exception:
        return None

def detect_subnet() -> Optional[str]:
    """Best-effort local subnet detection. Returns CIDR like '192.168.1.0/24' or None."""
    # 1) Try scapy if available
    try:
        from scapy.all import conf  # type: ignore
        # pick first route with a net and mask on IPv4
        for (net, mask, gw, iface, addr) in conf.route.routes:
            if isinstance(net, int):
                # scapy may store as int; skip
                continue
            if addr and net and mask != 0:
                try:
                    ip = ipaddress.ip_address(addr)
                    if ip.version == 4:
                        network = ipaddress.IPv4Network((addr, mask), strict=False)
                        return str(network)
                except Exception:
                    continue
    except Exception:
        pass

    system = platform.system().lower()

    # 2) Linux: ip addr
    if system == "linux" and _which("ip"):
        out = _run("ip -o -4 addr show up scope global")
        # e.g., "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 ..."
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", out)
        if m:
            cidr = m.group(1)
            network = str(ipaddress.IPv4Interface(cidr).network)
            return network

    # 3) macOS: ifconfig (netmask hex like 0xffffff00)
    if system == "darwin" and _which("ifconfig"):
        out = _run("ifconfig")
        for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-fA-F]{8})", out):
            ip_str = m.group(1)
            hexmask = m.group(2)
            mask_parts = [int(hexmask[i:i+2], 16) for i in range(0, 8, 2)]
            cidr_bits = "".join(f"{p:08b}" for p in mask_parts).count("1")
            network = str(ipaddress.IPv4Network(f"{ip_str}/{cidr_bits}", strict=False))
            if not ip_str.startswith("127."):
                return network

    # 4) Windows: ipconfig
    if system == "windows" and _which("ipconfig"):
        out = _run("ipconfig")
        # Capture IPv4 and Subnet Mask in the same adapter section
        blocks = re.split(r"\r?\n\r?\n", out)
        for b in blocks:
            if "IPv4 Address" in b or "IPv4-adres" in b:
                ip_m = re.search(r"IPv4 Address.*?:\s*([\d\.]+)", b)
                mask_m = re.search(r"Subnet Mask.*?:\s*([\d\.]+)", b)
                if ip_m and mask_m:
                    ip_str = ip_m.group(1)
                    mask_str = mask_m.group(1)
                    cidr = _netmask_to_cidr(mask_str)
                    if cidr and not ip_str.startswith("127."):
                        network = str(ipaddress.IPv4Network(f"{ip_str}/{cidr}", strict=False))
                        return network

    return None

async def _ping(ip: str, timeout: float) -> bool:
    system = platform.system().lower()
    if system == "windows":
        # -n count, -w timeout(ms)
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        # -c count, -W timeout(s); mac uses -W in ms? Use -t 1 fallback; prefer timeout(1)
        if _which("timeout"):
            cmd = ["timeout", str(int(max(timeout, 1))), "ping", "-c", "1", "-W", str(int(timeout)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await proc.wait()
        return proc.returncode == 0
    except Exception:
        return False

def _parse_neighbors() -> Dict[str, str]:
    """Map IP -> MAC from neighbor/ARP cache."""
    system = platform.system().lower()
    mapping: Dict[str, str] = {}

    if system == "linux" and _which("ip"):
        out = _run("ip -o neigh")
        # e.g., "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        for ip, mac in re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]{17})", out, flags=re.I):
            mapping[ip] = mac.lower()
    else:
        out = _run("arp -an")
        # e.g., "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0"
        for ip, mac in re.findall(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})", out, flags=re.I):
            mapping[ip] = mac.lower()

    return mapping

async def ping_sweep(cidr: str, timeout: float, concurrency: int, rdns: bool) -> List[Host]:
    net = ipaddress.IPv4Network(cidr, strict=False)
    sem = asyncio.Semaphore(concurrency)
    live: List[str] = []

    async def worker(ip: str):
        async with sem:
            if await _ping(ip, timeout):
                live.append(ip)

    tasks = []
    for ip in (str(h) for h in net.hosts()):
        tasks.append(asyncio.create_task(worker(ip)))
    await asyncio.gather(*tasks)

    neighbors = _parse_neighbors()

    results: List[Host] = []
    if rdns:
        for ip in sorted(live, key=lambda s: tuple(map(int, s.split(".")))):
            try:
                hostname = socket.getfqdn(ip)
            except Exception:
                hostname = None
            results.append(Host(ip=ip, mac=neighbors.get(ip), hostname=hostname, method="ping"))
    else:
        for ip in sorted(live, key=lambda s: tuple(map(int, s.split(".")))):
            results.append(Host(ip=ip, mac=neighbors.get(ip), method="ping"))
    return results

def arp_scan(cidr: str, rdns: bool) -> List[Host]:
    try:
        from scapy.all import ARP, Ether, srp, conf  # type: ignore
    except Exception as e:
        raise RuntimeError("Scapy not available. Install with `pip install scapy` or use --method ping.") from e

    # Why: ARP requires admin privileges; otherwise results may be incomplete.
    if not _is_root() and os.name != "nt":
        print("[warn] ARP scan without root may miss hosts.", file=sys.stderr)

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(cidr))
    ans, _ = srp(packet, timeout=2, verbose=False)
    hosts: List[Host] = []
    for _, recv in ans:
        ip = recv.psrc
        mac = recv.hwsrc.lower()
        hostname = None
        if rdns:
            try:
                hostname = socket.getfqdn(ip)
            except Exception:
                pass
        hosts.append(Host(ip=ip, mac=mac, hostname=hostname, method="arp"))
    # Sort numeric by IP
    hosts.sort(key=lambda h: tuple(map(int, h.ip.split("."))))
    return hosts

def print_table(hosts: List[Host]) -> None:
    if not hosts:
        print("No devices found.")
        return
    headers = ["IP", "MAC", "Hostname", "Method"]
    rows = [(h.ip, h.mac or "", h.hostname or "", h.method) for h in hosts]

    # compute column widths
    widths = [max(len(str(h)) for h in col) for col in zip(headers, *rows)]
    fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*r))

def save_json(hosts: List[Host], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(h) for h in hosts], f, indent=2)

def save_csv(hosts: List[Host], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "mac", "hostname", "method"])
        writer.writeheader()
        for h in hosts:
            writer.writerow(asdict(h))

def choose_method(method: str) -> str:
    if method != "auto":
        return method
    try:
        import scapy  # noqa: F401
        return "arp"
    except Exception:
        return "ping"

def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Scan local network and list connected devices.")
    parser.add_argument("--cidr", help="CIDR to scan, e.g., 192.168.1.0/24. Auto-detect if omitted.")
    parser.add_argument("--method", choices=["auto", "arp", "ping"], default="auto", help="Scan method.")
    parser.add_argument("--rdns", action="store_true", help="Perform reverse DNS lookups.")
    parser.add_argument("--timeout", type=float, default=1.0, help="Ping timeout seconds (ping mode).")
    parser.add_argument("--concurrency", type=int, default=256, help="Concurrent pings (ping mode).")
    parser.add_argument("--json", dest="json_out", help="Save results to JSON file.")
    parser.add_argument("--csv", dest="csv_out", help="Save results to CSV file.")
    args = parser.parse_args(list(argv) if argv is not None else None)

    cidr = args.cidr or detect_subnet()
    if not cidr:
        print("ERROR: Could not auto-detect your subnet. Pass --cidr like 192.168.1.0/24", file=sys.stderr)
        return 2

    # normalize CIDR to network address
    try:
        cidr = str(ipaddress.IPv4Network(cidr, strict=False))
    except Exception:
        print(f"ERROR: Invalid CIDR: {cidr}", file=sys.stderr)
        return 2

    method = choose_method(args.method)

    try:
        if method == "arp":
            hosts = arp_scan(cidr, rdns=args.rdns)
        else:
            hosts = asyncio.run(ping_sweep(cidr, timeout=args.timeout, concurrency=args.concurrency, rdns=args.rdns))
    except KeyboardInterrupt:
        print("\nScan cancelled.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # Dedupe by IP (prefer ARP info if present)
    merged: Dict[str, Host] = {}
    for h in hosts:
        if h.ip in merged:
            # prefer MAC known and hostname set
            cur = merged[h.ip]
            if not cur.mac and h.mac:
                cur.mac = h.mac
            if (not cur.hostname) and h.hostname:
                cur.hostname = h.hostname
            if cur.method != "arp" and h.method == "arp":
                cur.method = "arp"
        else:
            merged[h.ip] = h
    final_hosts = [merged[k] for k in sorted(merged.keys(), key=lambda s: tuple(map(int, s.split("."))))]

    print_table(final_hosts)

    if args.json_out:
        save_json(final_hosts, args.json_out)
        print(f"\nSaved JSON: {args.json_out}")
    if args.csv_out:
        save_csv(final_hosts, args.csv_out)
        print(f"Saved CSV: {args.csv_out}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

