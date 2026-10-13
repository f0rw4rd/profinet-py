#!/usr/bin/env python3
"""Exercise primary and backup ARs against the p-net echo device.

Set PROFINET_PRIMARY_IP and PROFINET_SECONDARY_IP to two local interface
addresses in the device subnet before running this example.
"""

import os
import subprocess
import sys

# Add parent directory to path for development
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from profinet import (
    IOCRSetup,
    IOSlot,
    ethernet_socket,
    get_mac,
    get_station_info,
)
from profinet.system_redundancy import PLC, SystemRedundancy

# p-net echo module from the opened cyclic example (slot 1, subslot 4)
ECHO_SLOT = 1
ECHO_SUBSLOT = 4
ECHO_MOD_IDENT = 0x00000040
ECHO_SUBMOD_IDENT = 0x00000140
ECHO_DATA_LENGTH = 4
CYCLE_TIME_MS = int(os.environ.get("PROFINET_CYCLE_MS", "128"))


def detect_container_bridge():
    """Detect the host-side bridge for the p-net test device."""
    try:
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.NetworkID}}{{end}}",
                "profinet-test-device",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        network_id = result.stdout.strip()
        if network_id:
            bridge = f"br-{network_id[:12]}"
            check = subprocess.run(
                ["ip", "link", "show", bridge],
                capture_output=True,
                timeout=5,
            )
            if check.returncode == 0:
                return bridge
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return "eth0"


def main():
    device = os.environ.get("PROFINET_DEVICE", "test-pn-device")
    interface = os.environ.get("PROFINET_IFACE", "") or detect_container_bridge()
    primary_ip = os.environ.get("PROFINET_PRIMARY_IP")
    secondary_ip = os.environ.get("PROFINET_SECONDARY_IP")
    if not primary_ip or not secondary_ip:
        print(
            "Set PROFINET_PRIMARY_IP and PROFINET_SECONDARY_IP to two local "
            "addresses in the device subnet."
        )
        return

    print(f"[1] Discovering '{device}' on {interface}...")
    sock = ethernet_socket(interface)
    src_mac = get_mac(interface)
    try:
        info = get_station_info(sock, src_mac, device, timeout_sec=5)
    except Exception as error:
        print(f"    Discovery failed: {error}")
        return
    finally:
        sock.close()

    print(f"    Found: {info.name} at {info.ip}")
    iocr_setup = IOCRSetup(
        slots=[
            IOSlot(
                slot=ECHO_SLOT,
                subslot=ECHO_SUBSLOT,
                module_ident=ECHO_MOD_IDENT,
                submodule_ident=ECHO_SUBMOD_IDENT,
                input_length=ECHO_DATA_LENGTH,
                output_length=ECHO_DATA_LENGTH,
            ),
        ],
        send_clock_factor=32,
        reduction_ratio=CYCLE_TIME_MS,
        watchdog_factor=10,
        data_hold_factor=10,
    )
    print(
        f"[2] Echo IO: slot={ECHO_SLOT}, subslot={ECHO_SUBSLOT}, "
        f"module=0x{ECHO_MOD_IDENT:08X}, submodule=0x{ECHO_SUBMOD_IDENT:08X}, "
        f"size={ECHO_DATA_LENGTH}B"
    )

    sys_red = SystemRedundancy(
        info=info,
        interface=interface,
        primary_ip=primary_ip,
        secondary_ip=secondary_ip,
        src_mac=src_mac,
        iocr_setup=iocr_setup,
    )
    try:
        print("[3] Connecting primary PLC A...")
        sys_red.connect(plc=PLC.A)
        sys_red.start(plc=PLC.A)
        sys_red.parameterize(plc=PLC.A, confirm_app_ready=True)

        print("[4] Connecting backup PLC B...")
        sys_red.connect(plc=PLC.B)
        sys_red.start(plc=PLC.B)
        sys_red.parameterize(plc=PLC.B, confirm_app_ready=True)

        print("[5] Switching over to PLC B...")
        sys_red.switchover(target=PLC.B, wait_for_ack=True)
    finally:
        print("[6] Stopping cyclic IO and closing connections...")
        sys_red.close()

    print("Done.")


if __name__ == "__main__":
    main()
