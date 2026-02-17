#!/usr/bin/env python3
"""
Connect to PROFINET device by IP address.

Note: from_ip() still uses DCP internally (needs root).
For root-free operation, use direct RPC connection (see below).
"""

import os
import sys

from profinet import PermissionDeniedError, ProfinetDevice

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")
DEVICE_IP = os.environ.get("PROFINET_IP", "192.168.1.100")

try:
    # This uses DCP to resolve IP -> device info (needs root)
    device = ProfinetDevice.from_ip(DEVICE_IP, INTERFACE)
except PermissionDeniedError:
    print("ERROR: DCP requires root even for IP lookup")
    print("\nFor root-free operation, use direct RPC:")
    print("  See 15_direct_rpc_no_root.py")
    sys.exit(1)

with device:
    print(f"Connected to: {device.name} ({device.ip})")

    # Read I&M0
    im0 = device.read_im0()
    print(f"Order ID: {im0.order_id}")
    print(f"Serial: {im0.im_serial_number}")
