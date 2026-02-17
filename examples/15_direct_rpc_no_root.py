#!/usr/bin/env python3
"""
EPM lookup without root privileges.

EPM (Endpoint Mapper) uses UDP port 34964, which doesn't need root.
This can be used to query device info when you only have an IP.

Note: Full RPC connection requires vendor/device IDs from DCP discovery.
For read/write operations, use ProfinetDevice.discover() which handles this.
"""

import os

from profinet import epm_lookup

DEVICE_IP = os.environ.get("PROFINET_IP", "192.168.1.100")

print(f"Querying EPM on {DEVICE_IP} (no root needed)...\n")

# EPM lookup - works without DCP, uses UDP socket
endpoints = epm_lookup(DEVICE_IP, timeout=3.0)

if not endpoints:
    print("No EPM response (device may not support EPM)")
    print("\nTo read I&M data, use DCP discovery:")
    print("  from profinet import ProfinetDevice")
    print("  with ProfinetDevice.from_ip(ip, interface) as dev:")
    print("      print(dev.read_im0())")
else:
    print(f"Found {len(endpoints)} endpoint(s):\n")
    for ep in endpoints:
        print(f"Interface: {ep.interface_name}")
        print(f"  UUID: {ep.interface_uuid}")
        print(f"  Version: {ep.interface_version_major}.{ep.interface_version_minor}")
        print(f"  Protocol: {ep.protocol}")
        print(f"  Port: {ep.port}")
        if ep.annotation:
            print(f"  Device Model: {ep.annotation}")
        print()
