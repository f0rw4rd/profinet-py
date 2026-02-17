#!/usr/bin/env python3
"""Discover device topology (slots, subslots, ports)."""

import os

from profinet import ProfinetDevice

INTERFACE = os.environ.get("PROFINET_IFACE", "eth0")
DEVICE = os.environ.get("PROFINET_DEVICE", "my-device")

with ProfinetDevice.discover(DEVICE, INTERFACE) as device:
    print(f"Discovering topology of {device.name}...\n")

    # Discover all slots/subslots
    slots = device.discover_slots()
    print(f"Found {len(slots)} slot/subslot combinations:")
    for slot in slots:
        print(f"  API {slot.api}, Slot {slot.slot}, Subslot 0x{slot.subslot:04X}")
        print(f"    Module: 0x{slot.module_ident:08X}")
        print(f"    Submodule: 0x{slot.submodule_ident:08X}")

    # Read physical topology
    print("\nPhysical Topology (PDRealData):")
    topology = device.read_topology()

    if topology.interface:
        iface = topology.interface
        print("\n  Interface:")
        print(f"    Chassis ID: {iface.chassis_id}")
        print(f"    MAC: {iface.mac_str}")
        print(f"    IP: {iface.ip_str}")
        print(f"    Subnet: {iface.subnet_str}")

    for port in topology.ports:
        print(f"\n  Port {port.port_id}:")
        print(f"    Slot/Subslot: {port.slot}/0x{port.subslot:04X}")
        print(f"    Link State: {port.link_state}")
        print(f"    MAU Type: {port.mau_type_name}")
        for peer in port.peers:
            print(f"    Peer: {peer.chassis_id} / {peer.port_id}")
