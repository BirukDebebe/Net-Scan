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
    


