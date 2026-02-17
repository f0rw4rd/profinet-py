#!/usr/bin/env python3
"""Write I&M1 and I&M2 records to device."""

import os

from profinet import ProfinetDevice

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")
DEVICE = os.environ.get("PROFINET_DEVICE", "my-device")

with ProfinetDevice.discover(DEVICE, INTERFACE) as device:
    print(f"Writing I&M records to {device.name}...")

    # Write I&M1 (tag function and location)
    device.write_im1(
        tag_function="Pump Control",
        tag_location="Building A, Floor 2",
    )
    print("I&M1 written")

    # Write I&M2 (installation date)
    device.write_im2(date="2024-01-15 10:30")
    print("I&M2 written")

    # Verify writes
    im1 = device.read_im1()
    im2 = device.read_im2()

    print("\nVerified I&M1:")
    print(f"  Tag Function: {im1.tag_function}")
    print(f"  Tag Location: {im1.tag_location}")
    print("\nVerified I&M2:")
    print(f"  Installation Date: {im2.installation_date}")
