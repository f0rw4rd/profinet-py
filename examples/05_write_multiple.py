#!/usr/bin/env python3
"""Write multiple records atomically using IODWriteMultiple."""

import os
import struct

from profinet import ProfinetDevice, WriteItem

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")
DEVICE = os.environ.get("PROFINET_DEVICE", "my-device")


def build_im1_data(tag_function: str, tag_location: str) -> bytes:
    """Build I&M1 record data."""
    header = struct.pack(">HHBB", 0x0021, 58, 0x01, 0x00)
    padding = b"\x00\x00"
    func = tag_function.encode("latin-1")[:32].ljust(32, b"\x20")
    loc = tag_location.encode("latin-1")[:22].ljust(22, b"\x20")
    return header + padding + func + loc


def build_im2_data(date: str) -> bytes:
    """Build I&M2 record data."""
    header = struct.pack(">HHBB", 0x0022, 20, 0x01, 0x00)
    padding = b"\x00\x00"
    date_bytes = date.encode("latin-1")[:16].ljust(16, b"\x20")
    return header + padding + date_bytes


with ProfinetDevice.discover(DEVICE, INTERFACE) as device:
    print(f"Writing multiple records to {device.name}...")

    # Prepare writes
    writes = [
        WriteItem(
            slot=0,
            subslot=1,
            index=0xAFF1,
            data=build_im1_data("Motor Control", "Hall B"),
        ),
        WriteItem(
            slot=0,
            subslot=1,
            index=0xAFF2,
            data=build_im2_data("2024-06-20 14:00"),
        ),
    ]

    # Execute atomic write
    results = device.write_multiple(writes)

    # Check results
    for r in results:
        status = "OK" if r.success else f"FAIL (0x{r.status:08X})"
        print(f"  Index 0x{r.index:04X}: {status}")

    print(f"\nAll writes successful: {all(r.success for r in results)}")
