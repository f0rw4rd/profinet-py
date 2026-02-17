#!/usr/bin/env python3
"""Complete workflow: discover, read, write, verify."""

import os

from profinet import ProfinetDevice

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")
DEVICE = os.environ.get("PROFINET_DEVICE", "my-device")

print("=" * 60)
print("PROFINET Full Workflow Example")
print("=" * 60)

# 1. Discover and connect
print("\n[1] Discovering device...")
device = ProfinetDevice.discover(DEVICE, INTERFACE)

with device:
    print(f"    Connected to {device.name} ({device.ip})")

    # 2. Get device info
    print("\n[2] Reading device info...")
    info = device.get_info(include_topology=True)
    print(f"    Order ID: {info.order_id}")
    print(f"    Serial: {info.serial_number}")
    print(f"    SW Version: {info.software_revision}")

    # 3. Check configuration
    print("\n[3] Checking module configuration...")
    diff = device.read_module_diff()
    if diff.all_ok:
        print("    Configuration: OK")
    else:
        print("    Configuration: MISMATCH")
        for s, ss, state in diff.get_mismatches():
            print(f"      Slot {s}, Subslot 0x{ss:04X}: {state}")

    # 4. Read diagnosis
    print("\n[4] Reading diagnosis...")
    diag = device.read_diagnosis()
    if diag.entries:
        print(f"    Found {len(diag.entries)} diagnosis entries")
    else:
        print("    No active diagnosis (device healthy)")

    # 5. Check for alarms
    print("\n[5] Checking alarms...")
    alarm = device.read_alarm()
    if alarm:
        print(f"    Alarm: {alarm.alarm_type_name} at {alarm.location}")
    else:
        print("    No alarms")

    # 6. Discover slots
    print("\n[6] Discovering slots...")
    slots = device.discover_slots()
    print(f"    Found {len(slots)} slot/subslot combinations")

    # 7. Read topology
    print("\n[7] Reading topology...")
    if info.topology:
        print(f"    Ports: {len(info.topology.ports)}")
        for port in info.topology.ports:
            print(f"      {port.port_id}: {port.link_state}")

print("\n" + "=" * 60)
print("Workflow complete")
print("=" * 60)
