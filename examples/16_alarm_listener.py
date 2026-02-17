#!/usr/bin/env python3
"""
Alarm Listener Example.

Demonstrates async alarm reception from PROFINET devices.
Uses AlarmCR (Alarm Connection Relationship) established during AR setup.

Requires root privileges for raw socket access.
Run with: sudo python3 16_alarm_listener.py

Press Ctrl+C to stop.
"""

import os
import signal
import sys
import time

from profinet import (
    AlarmNotification,
    PermissionDeniedError,
    ProfinetDevice,
)

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")
DEVICE = os.environ.get("PROFINET_DEVICE", "")

# Flag for clean shutdown
running = True


def handle_alarm(alarm: AlarmNotification) -> None:
    """Callback for received alarms."""
    print(f"\n{'=' * 60}")
    print(f"ALARM RECEIVED: {alarm.alarm_type_name}")
    print(
        f"  Location: API={alarm.api}, Slot={alarm.slot_number}, Subslot=0x{alarm.subslot_number:04X}"
    )
    print(f"  Module: 0x{alarm.module_ident_number:08X}")
    print(f"  Submodule: 0x{alarm.submodule_ident_number:08X}")
    print(f"  Sequence: {alarm.alarm_sequence_number}")
    print(f"  Priority: {'HIGH' if alarm.is_high_priority else 'LOW'}")

    if alarm.channel_diagnosis:
        print("  Flags: Channel Diagnosis")
    if alarm.manufacturer_specific:
        print("  Flags: Manufacturer Specific")

    if alarm.items:
        print(f"  Items: {len(alarm.items)}")
        for item in alarm.items:
            print(f"    - {item.usi_name} (0x{item.user_structure_id:04X})")
    print(f"{'=' * 60}\n")


def signal_handler(sig, frame):
    """Handle Ctrl+C."""
    global running
    print("\nShutting down...")
    running = False


def main():
    global running

    if not DEVICE:
        print("Usage: sudo PROFINET_DEVICE=<name_or_mac> python3 16_alarm_listener.py")
        print(
            "  Or:  sudo PROFINET_IFACE=eth0 PROFINET_DEVICE=my-device python3 16_alarm_listener.py"
        )
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        print(f"Discovering device '{DEVICE}' on {INTERFACE}...")
        device = ProfinetDevice.discover(DEVICE, INTERFACE)
        print(f"Found: {device.name} at {device.ip}")

    except PermissionDeniedError as e:
        print(f"Permission denied: {e}")
        print("\nRaw sockets require root privileges.")
        print("Run with: sudo python3 16_alarm_listener.py")
        sys.exit(1)

    try:
        with device:
            print(f"\nConnected to {device.name}")

            # Check if AlarmCR was established
            if not device._rpc._alarm_cr_enabled:
                print("Warning: AlarmCR not established by device")
                print("Device may not support async alarm notifications")
            else:
                print(f"AlarmCR established (device ref: {device._rpc._device_alarm_ref})")

            # Register alarm callback
            device.on_alarm(handle_alarm)

            # Start background alarm listener
            print("\nStarting alarm listener...")
            device.start_alarm_listener()
            print("Listening for alarms. Press Ctrl+C to stop.\n")

            # Check for existing alarms via polling
            print("Checking for existing alarms...")
            alarm = device.read_alarm()
            if alarm:
                print(f"Existing alarm: {alarm.alarm_type_name}")
                handle_alarm(alarm)
            else:
                print("No existing alarm present")

            # Wait for alarms
            print("\nWaiting for async alarm notifications...")
            while running:
                time.sleep(0.5)
                # Could also check device.alarm_listener_running here

            print("\nStopping alarm listener...")
            device.stop_alarm_listener()

    except Exception as e:
        print(f"\nError: {e}")
        raise


if __name__ == "__main__":
    main()
