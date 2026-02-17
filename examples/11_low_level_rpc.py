#!/usr/bin/env python3
"""Low-level RPC access using RPCCon directly."""

import os
import re

from profinet import (
    DCPDeviceDescription,
    RPCCon,
    ethernet_socket,
    get_mac,
    get_station_info,
    read_response,
    send_discover,
)

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")
DEVICE = os.environ.get("PROFINET_DEVICE", "my-device")

# Create raw socket and get MAC
sock = ethernet_socket(INTERFACE)
src_mac = get_mac(INTERFACE)

# Check if DEVICE is a MAC address
is_mac = bool(re.match(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", DEVICE))

try:
    if is_mac:
        # Discover all and find by MAC
        send_discover(sock, src_mac)
        responses = read_response(sock, src_mac, timeout_sec=3)
        mac_normalized = DEVICE.lower().replace("-", ":")
        info = None
        for mac, blocks in responses.items():
            dev = DCPDeviceDescription(mac, blocks)
            dev_mac = dev.mac if isinstance(dev.mac, str) else ":".join(f"{b:02x}" for b in dev.mac)
            if dev_mac.lower() == mac_normalized:
                info = dev
                break
        if not info:
            raise RuntimeError(f"Device with MAC '{DEVICE}' not found")
    else:
        # Discover by name
        info = get_station_info(sock, src_mac, DEVICE)
    print(f"Found: {info.name} at {info.ip}")
finally:
    sock.close()

# Create RPC connection
with RPCCon(info) as rpc:
    rpc.connect(src_mac)

    # Raw read by index
    raw = rpc.read_raw(idx=0xAFF0, slot=0, subslot=1)
    print(f"\nRaw I&M0 data: {len(raw)} bytes")

    # Read with full control
    iod = rpc.read(api=0, slot=0, subslot=1, idx=0xAFF0)
    print(f"IOD payload: {len(iod.payload)} bytes")

    # Write raw data
    # rpc.write(api=0, slot=0, subslot=1, idx=0xAFF3, data=b"Descriptor")

    # Enumerate available records
    print("\nEnumerating records:")
    records = rpc.enumerate_records()
    for idx, size in sorted(records.items()):
        print(f"  0x{idx:04X}: {size} bytes")
