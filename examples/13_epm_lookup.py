#!/usr/bin/env python3
"""Query EPM (Endpoint Mapper) for RPC endpoints."""

import os

from profinet import epm_lookup

DEVICE_IP = os.environ.get("PROFINET_IP", "192.168.1.100")

print(f"Querying EPM on {DEVICE_IP}...\n")

endpoints = epm_lookup(DEVICE_IP, timeout=3.0)

if not endpoints:
    print("No endpoints found (device may not support EPM)")
else:
    print(f"Found {len(endpoints)} endpoint(s):\n")
    for ep in endpoints:
        print(f"Interface: {ep.interface_name}")
        print(f"  UUID: {ep.interface_uuid}")
        print(f"  Version: {ep.interface_version_major}.{ep.interface_version_minor}")
        print(f"  Protocol: {ep.protocol}")
        print(f"  Port: {ep.port}")
        if ep.annotation:
            print(f"  Annotation: {ep.annotation}")
        print()
