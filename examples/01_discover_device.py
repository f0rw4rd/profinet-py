#!/usr/bin/env python3
"""
Discover PROFINET device by name and display info.

Note: DCP discovery requires root (raw ethernet). Use 00_scan_network.py
to find device names first, or use 02_discover_by_ip.py with known IP.

Run with: sudo python3 01_discover_device.py
"""

import os
import sys

from profinet import DCPDeviceNotFoundError, PermissionDeniedError, ProfinetDevice

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")
DEVICE = os.environ.get("PROFINET_DEVICE", "my-device")  # name or MAC

try:
    # Discover device by name or MAC (uses DCP - needs root)
    device = ProfinetDevice.discover(DEVICE, INTERFACE, timeout=5.0)
except PermissionDeniedError:
    print("ERROR: DCP discovery requires root privileges")
    print("Run with: sudo python3 01_discover_device.py")
    print("\nAlternatives:")
    print("  - Use 02_discover_by_ip.py if you know the IP (no root needed)")
    print("  - Run 00_scan_network.py first to find device names")
    sys.exit(1)
except DCPDeviceNotFoundError:
    print(f"ERROR: Device '{DEVICE}' not found")
    print("Run 00_scan_network.py to see available devices")
    sys.exit(1)

# Once discovered, RPC operations use UDP (no root needed)
with device:
    info = device.get_info()

    print(f"Device: {info.name}")
    print(f"IP: {info.ip}")
    print(f"MAC: {info.mac}")
    print(f"Vendor ID: 0x{info.vendor_id:04X}")
    print(f"Device ID: 0x{info.device_id:04X}")

    if info.im0:
        print("\nI&M0:")
        print(f"  Order ID: {info.order_id}")
        print(f"  Serial: {info.serial_number}")
        print(f"  HW Rev: {info.hardware_revision}")
        print(f"  SW Rev: {info.software_revision}")

    if info.annotation:
        print(f"\nEPM Annotation: {info.annotation}")
