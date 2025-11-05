# Net-Scan

A cross-platform, CLI network scanner that lists devices on a local subnet.  
Supports fast ARP scans (requires Scapy + admin) and portable ICMP/PING scans. Optional reverse DNS lookups and output to JSON/CSV.

## Features
- Auto subnet detection (best-effort) or explicit CIDR input
- Two scan methods: ARP (fast) and PING (portable)
- Optional reverse DNS lookups
- Save results as table, JSON, or CSV
- Runs on Windows, macOS, Linux

## Requirements
- Python 3.8+
- Optional (for ARP): scapy (pip install scapy)
- ARP scans require admin/root privileges on non-Windows platforms

## Quickstart (recommended)
Follow these steps to run the scanner:

1) Go to the folder with net_scan.py
```bash
cd path\to\your\project   # Windows
# or
cd /path/to/your/project  # macOS/Linux
```

2) (Recommended) create venv
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
```

3) (Only for ARP mode) install scapy
```bash
pip install scapy
```

4) Run it
```bash
# Ping (portable, no admin)
python net_scan.py --method ping --rdns

# ARP (faster, needs admin + scapy)
# Windows: open PowerShell **as Administrator**
# macOS/Linux: prefix with sudo
sudo python net_scan.py --method arp
```

## Usage examples
- Auto-detect subnet and pick best method:
  ```bash
  python net_scan.py
  ```
- Explicit CIDR, ping with reverse DNS:
  ```bash
  python net_scan.py --cidr 192.168.1.0/24 --method ping --rdns
  ```
- Save results:
  ```bash
  python net_scan.py --json hosts.json --csv hosts.csv
  ```

## Important notes & disclaimers
- Use this tool only on networks you own or have explicit permission to scan. Unauthorized scanning can be illegal and disruptive.
- ARP scanning may require administrative privileges and may produce incomplete results if run without them.
- On some systems the script auto-detection may be best-effort; pass `--cidr` to be explicit.

## Output
The script prints a table of discovered hosts with columns: IP, MAC, Hostname, Method. If requested, it can also save JSON/CSV files.


