#!/usr/bin/env python3
"""Read all I&M records from device."""

import os

from profinet import ProfinetDevice

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")
DEVICE = os.environ.get("PROFINET_DEVICE", "my-device")

with ProfinetDevice.discover(DEVICE, INTERFACE) as device:
    print(f"Reading I&M records from {device.name}...\n")

    # Read all available I&M records
    im_records = device.read_all_im()

    for name, record in im_records.items():
        print(f"{name.upper()}:")
        for field in dir(record):
            if not field.startswith("_") and field not in ("IDX", "fmt", "fmt_size"):
                val = getattr(record, field)
                if not callable(val):
                    print(f"  {field}: {val}")
        print()
