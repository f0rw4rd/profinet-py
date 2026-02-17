#!/usr/bin/env python3
"""
Discover all PROFINET devices on network using DCP.

No device name needed - this broadcasts to find ALL devices.
Run with: sudo python3 12_dcp_discovery.py
"""

import os

from profinet import (
    DCPDeviceDescription,
    PermissionDeniedError,
    ethernet_socket,
    get_mac,
    read_response,
    send_discover,
)

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")

try:
    sock = ethernet_socket(INTERFACE)
    src_mac = get_mac(INTERFACE)
except PermissionDeniedError as e:
    print(f"Permission denied: {e}")
    print("\nRaw ethernet sockets require root privileges.")
    print("Run with: sudo python3 12_dcp_discovery.py")
    exit(1)

try:
    print(f"Discovering PROFINET devices on {INTERFACE}...\n")

    # Send DCP discover broadcast - finds ALL devices, no name needed
    send_discover(sock, src_mac)

    # Read responses (wait 3 seconds)
    responses = read_response(sock, src_mac, timeout_sec=3)

    print(f"Found {len(responses)} device(s):\n")

    for mac, blocks in responses.items():
        dev = DCPDeviceDescription(mac, blocks)
        print(dev)
        print()

finally:
    sock.close()
