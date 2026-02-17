#!/usr/bin/env python3
"""
Cyclic IO Demo (RT_CLASS_1).

Demonstrates PROFINET cyclic data exchange using RT_CLASS_1 with:
- Explicit state machine (IDLE -> RUNNING -> STOPPING -> STOPPED)
- Double-buffered output data
- Cycle counter tracking (gap/duplicate detection)
- Watchdog with FAULT state transition
- IOCS acknowledgment of input data
- Graceful stop (sends STOP frames before closing)
- Separate TX/RX sockets

This example:
1. Discovers the device via DCP
2. Connects with IOCR blocks for cyclic IO
3. Sends PrmEnd to end parameter phase
4. Signals ApplicationReady (waits for device CControl)
5. Starts cyclic data exchange with full statistics

Works with the p-net Docker container (see tests/integration/docker-compose.yml)
or any PROFINET IO device with the correct slot/module configuration.

Requires root privileges for raw socket access.
Run with: sudo python3 18_cyclic_io.py

Press Ctrl+C to stop.
"""

import os
import signal
import subprocess
import sys
import time

# Add parent directory to path for development
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from profinet import (
    IOCRSetup,
    IOSlot,
    RPCCon,
    ethernet_socket,
    get_mac,
    get_station_info,
)
from profinet.cyclic import CyclicController
from profinet.rt import build_iocr_configs

# Device configuration
DEVICE = os.environ.get("PROFINET_DEVICE", "test-pn-device")
INTERFACE = os.environ.get("PROFINET_IFACE", "")  # auto-detect if empty

# p-net echo module (slot 4, subslot 1, 8B input + 8B output)
# See tests/integration/docker-compose.yml for the Docker container setup.
ECHO_SLOT = 4
ECHO_SUBSLOT = 1
ECHO_MOD_IDENT = 0x00000040
ECHO_SUBMOD_IDENT = 0x00000140
ECHO_INPUT_LEN = 8
ECHO_OUTPUT_LEN = 8

# Cycle time in ms
# WARNING: Python has timing limitations due to the GIL and OS scheduling!
# - 128ms: Safe for container testing (default)
# - 32ms:  Reliable on all systems with real hardware
# - 16ms:  Usually works, may have minor jitter
# - 8ms:   Minimum practical, expect some jitter under load
# - <8ms:  NOT RECOMMENDED - will have timing issues
CYCLE_TIME_MS = int(os.environ.get("PROFINET_CYCLE_MS", "128"))

# Flag for clean shutdown
running = True


def signal_handler(sig, frame):
    """Handle Ctrl+C."""
    global running
    print("\nShutting down...")
    running = False


def detect_container_bridge():
    """Detect Docker bridge interface for profinet-test-device container.

    Returns the host-side bridge interface name (br-<id>) or falls back to eth0.
    """
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
            # Verify interface exists
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
    global running

    # Auto-detect interface if not set
    interface = INTERFACE or detect_container_bridge()

    if not DEVICE:
        print("Usage: sudo PROFINET_DEVICE=<name> python3 18_cyclic_io.py")
        print("  Or:  sudo PROFINET_IFACE=eth0 PROFINET_DEVICE=my-device python3 18_cyclic_io.py")
        print("\nEnvironment variables:")
        print(f"  PROFINET_IFACE      - Network interface (auto-detected: {interface})")
        print("  PROFINET_DEVICE     - Device station name (default: test-pn-device)")
        print("  PROFINET_CYCLE_MS   - Cycle time in ms (default: 128)")
        sys.exit(1)

    # Warn if cycle time is too low
    if CYCLE_TIME_MS < 8:
        print(f"\n*** WARNING: Cycle time {CYCLE_TIME_MS}ms is below 8ms! ***")
        print("Python cannot reliably achieve this timing. Expect failures.")
        print("Consider using PROFINET_CYCLE_MS=32 for reliable operation.\n")

    signal.signal(signal.SIGINT, signal_handler)

    # ---- Step 1: Discover device ----
    print(f"[1] Discovering '{DEVICE}' on {interface}...")
    sock = ethernet_socket(interface)
    src_mac = get_mac(interface)
    try:
        info = get_station_info(sock, src_mac, DEVICE, timeout_sec=5)
    except Exception as e:
        print(f"    Discovery failed: {e}")
        sys.exit(1)
    finally:
        sock.close()

    dst_mac = info.mac if isinstance(info.mac, bytes) else bytes.fromhex(info.mac.replace(":", ""))
    print(f"    Found: {info.name} at {info.ip}")
    print(f"    MAC: {':'.join(f'{b:02x}' for b in dst_mac)}")

    # ---- Step 2: Configure IOCR ----
    print(f"\n[2] Configuring IOCR (cycle={CYCLE_TIME_MS}ms)...")

    send_clock_factor = 32  # 1ms base (31.25us * 32 = 1ms)
    reduction_ratio = CYCLE_TIME_MS

    # Echo module: 8B input + 8B output at slot 4
    # Adjust these for your device! Use discover_slots() or GSDML to find
    # the correct module/submodule IDs and IO sizes.
    iocr_setup = IOCRSetup(
        slots=[
            IOSlot(
                slot=ECHO_SLOT,
                subslot=ECHO_SUBSLOT,
                module_ident=ECHO_MOD_IDENT,
                submodule_ident=ECHO_SUBMOD_IDENT,
                input_length=ECHO_INPUT_LEN,
                output_length=ECHO_OUTPUT_LEN,
            ),
        ],
        send_clock_factor=send_clock_factor,
        reduction_ratio=reduction_ratio,
        watchdog_factor=10,
        data_hold_factor=10,
    )

    for s in iocr_setup.slots:
        print(
            f"    Slot {s.slot}: mod=0x{s.module_ident:08X} sub=0x{s.submodule_ident:08X} "
            f"in={s.input_length}B out={s.output_length}B"
        )

    # ---- Step 3: Connect with IOCR ----
    print("\n[3] Connecting with IOCR...")
    rpc = RPCCon(info, timeout=10.0)
    try:
        result = rpc.connect(
            src_mac=src_mac,
            with_alarm_cr=True,
            iocr_setup=iocr_setup,
        )
    except Exception as e:
        print(f"    Connect failed: {e}")
        rpc.close()
        sys.exit(1)

    if not result or not result.has_cyclic:
        print("    No cyclic IO established")
        rpc.close()
        sys.exit(1)

    print(f"    Input Frame ID:  0x{result.input_frame_id:04X}")
    print(f"    Output Frame ID: 0x{result.output_frame_id:04X}")

    # ---- Step 4: PrmEnd ----
    print("\n[4] PrmEnd...")
    try:
        rpc.prm_end()
        print("    OK")
    except Exception as e:
        print(f"    Failed: {e}")
        rpc.close()
        sys.exit(1)

    # ---- Step 5: ApplicationReady ----
    print("\n[5] ApplicationReady (waiting for device CControl)...")
    try:
        rpc.application_ready(timeout=30.0)
        print("    OK - device in RUN state")
    except Exception as e:
        print(f"    Failed: {e}")
        rpc.close()
        sys.exit(1)

    # ---- Step 6: Build IOCRConfigs and start cyclic ----
    print(f"\n[6] Starting cyclic exchange ({CYCLE_TIME_MS}ms cycle)...")

    input_iocr, output_iocr = build_iocr_configs(
        iocr_setup.slots,
        result.input_frame_id,
        result.output_frame_id,
        send_clock_factor=iocr_setup.send_clock_factor,
        reduction_ratio=iocr_setup.reduction_ratio,
        watchdog_factor=iocr_setup.watchdog_factor,
    )

    cyclic = CyclicController(
        interface=interface,
        src_mac=src_mac,
        dst_mac=dst_mac,
        input_iocr=input_iocr,
        output_iocr=output_iocr,
        max_consecutive_timeouts=10,
    )

    # Register callbacks
    def on_state_change(old, new):
        print(f"    State: {old.value} -> {new.value}")

    def on_timeout():
        pass  # handled by stats

    def on_error(msg):
        print(f"    ERROR: {msg}")

    cyclic.on_state_change(on_state_change)
    cyclic.on_timeout(on_timeout)
    cyclic.on_error(on_error)

    # Set initial output data (8B echo pattern)
    cyclic.set_output_data(ECHO_SLOT, ECHO_SUBSLOT, b"\x00" * ECHO_OUTPUT_LEN)

    cyclic.start()
    print("    Press Ctrl+C to stop.\n")

    # ---- Step 7: Run - read inputs, update outputs ----
    last_print = time.time()
    counter = 0

    while running:
        time.sleep(0.5)

        # Read echo input data
        echo_in = cyclic.get_input_data(ECHO_SLOT, ECHO_SUBSLOT)

        # Update output with incrementing echo pattern
        counter = (counter + 1) & 0xFF
        pattern = bytes([counter] * ECHO_OUTPUT_LEN)
        cyclic.set_output_data(ECHO_SLOT, ECHO_SUBSLOT, pattern)

        # Print status every 5 seconds
        now = time.time()
        if now - last_print >= 5.0:
            last_print = now
            s = cyclic.stats
            echo_hex = echo_in.hex() if echo_in else "--"
            print(
                f"[{cyclic.state.value:>8s}] "
                f"TX={s.frames_sent:<6d} RX={s.frames_received:<6d} "
                f"missed={s.frames_missed} dup={s.frames_duplicate} "
                f"ooo={s.frames_out_of_order} inv={s.frames_invalid} "
                f"jitter={s.max_jitter_us}us | "
                f"echo_in={echo_hex} out=0x{counter:02X}"
            )

    # ---- Step 8: Graceful stop ----
    print("\n[8] Stopping cyclic exchange...")
    cyclic.stop()

    s = cyclic.stats
    print("\n    Final statistics:")
    print(f"      Frames sent:       {s.frames_sent}")
    print(f"      Frames received:   {s.frames_received}")
    print(f"      Frames missed:     {s.frames_missed}")
    print(f"      Frames duplicate:  {s.frames_duplicate}")
    print(f"      Frames out-of-order: {s.frames_out_of_order}")
    print(f"      Frames invalid:    {s.frames_invalid}")
    print(f"      Avg cycle time:    {s.avg_cycle_time_us}us")
    print(f"      Max jitter:        {s.max_jitter_us}us")
    if s._cycle_count > 0:
        print(f"      Min cycle time:    {s.min_cycle_time_us}us")
        print(f"      Max cycle time:    {s.max_cycle_time_us}us")

    # Cleanup
    print("\n    Disconnecting...")
    rpc.close()
    print("    Done.")


if __name__ == "__main__":
    main()
