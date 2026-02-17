#!/usr/bin/env python3
"""Read ModuleDiffBlock to check device configuration status."""

import os

from profinet import ProfinetDevice

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")
DEVICE = os.environ.get("PROFINET_DEVICE", "my-device")

with ProfinetDevice.discover(DEVICE, INTERFACE) as device:
    print(f"Checking configuration on {device.name}...\n")

    diff = device.read_module_diff()

    if diff.all_ok:
        print("Configuration OK - all modules match expected config")
    else:
        print("Configuration MISMATCH:")
        for slot, subslot, state in diff.get_mismatches():
            print(f"  Slot {slot}, Subslot 0x{subslot:04X}: {state}")

    # Show detailed info
    print("\nDetailed module status:")
    for mod in diff.modules:
        status = "OK" if mod.is_proper else mod.state_name
        print(f"  Slot {mod.slot_number}: Module 0x{mod.module_ident_number:08X} - {status}")
        for sub in mod.submodules:
            sub_status = "OK" if sub.is_ok else sub.state_name
            print(f"    Subslot 0x{sub.subslot_number:04X}: {sub_status}")
