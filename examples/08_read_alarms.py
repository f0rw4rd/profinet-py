#!/usr/bin/env python3
"""Read alarm notifications from device."""

import os

from profinet import ProfinetDevice
from profinet.alarms import DiagnosisItem, MaintenanceItem, PE_AlarmItem

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")
DEVICE = os.environ.get("PROFINET_DEVICE", "my-device")

with ProfinetDevice.discover(DEVICE, INTERFACE) as device:
    print(f"Reading alarms from {device.name}...\n")

    alarm = device.read_alarm(slot=0, subslot=0)

    if alarm is None:
        print("No alarm present")
    else:
        print(f"Alarm Type: {alarm.alarm_type_name}")
        print(f"Location: {alarm.location}")
        print(f"Sequence: {alarm.alarm_sequence_number}")
        print(f"Priority: {'High' if alarm.is_high_priority else 'Low'}")

        print(f"\nAlarm Items ({len(alarm.items)}):")
        for item in alarm.items:
            print(f"  USI: 0x{item.user_structure_id:04X} ({item.usi_name})")

            if isinstance(item, DiagnosisItem):
                print(f"    Channel: {item.channel_number_value}")
                print(f"    Error Type: 0x{item.channel_error_type:04X}")
                if item.is_extended:
                    print(f"    Ext Error: 0x{item.ext_channel_error_type:04X}")

            elif isinstance(item, MaintenanceItem):
                print(f"    Required: {item.maintenance_required}")
                print(f"    Demanded: {item.maintenance_demanded}")

            elif isinstance(item, PE_AlarmItem):
                print(f"    PE Mode: {item.mode_name}")
