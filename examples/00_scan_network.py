#!/usr/bin/env python3
"""
Scan network for all PROFINET devices - simplest example.

DCP uses raw ethernet frames, so requires root.
Run with: sudo python3 00_scan_network.py
"""

import os
import sys

from profinet import PermissionDeniedError, scan

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")

try:
    print(f"Scanning {INTERFACE} for PROFINET devices...\n")

    count = 0
    for device in scan(INTERFACE):
        print(f"  {device.name:20} {device.ip:15} {device.mac}")
        count += 1

    if count == 0:
        print("No devices found")
    else:
        print(f"\nFound {count} device(s)")

except PermissionDeniedError:
    print("ERROR: Raw sockets require root privileges")
    print()
    print("Options:")
    print("  1. Run with sudo: sudo python3 00_scan_network.py")
    print("  2. Set CAP_NET_RAW: sudo setcap cap_net_raw+ep $(which python3)")
    print("  3. If you know the IP, use 15_direct_rpc_no_root.py")
    sys.exit(1)
except OSError as e:
    print(f"ERROR: {e}")
    print(f"Check that interface '{INTERFACE}' exists")
    sys.exit(1)
