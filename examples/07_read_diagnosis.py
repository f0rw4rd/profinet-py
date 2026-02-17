#!/usr/bin/env python3
"""Read diagnosis data from device."""

import os

from profinet import ProfinetDevice

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")
DEVICE = os.environ.get("PROFINET_DEVICE", "my-device")

with ProfinetDevice.discover(DEVICE, INTERFACE) as device:
    print(f"Reading diagnosis from {device.name}...\n")

    # Read all diagnosis from all indices
    all_diag = device.read_all_diagnosis()

    if not all_diag:
        print("No diagnosis entries found (device OK)")
    else:
        for index, diag in all_diag.items():
            print(f"Index 0x{index:04X}:")
            for entry in diag.entries:
                print(f"  Channel {entry.channel_number}: {entry.error_type_name}")
                if hasattr(entry, "ext_error_type_name"):
                    print(f"    Extended: {entry.ext_error_type_name}")
            print()

    # Single diagnosis read
    diag = device.read_diagnosis(slot=0, subslot=0, index=0xF000)
    print(f"Device-level diagnosis (0xF000): {len(diag.entries)} entries")
