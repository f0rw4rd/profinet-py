#!/usr/bin/env python3
"""
Hardware test: Cyclic IO with real E-T-A PROFINET device.

This script tests the full cyclic IO flow:
1. Discover device via DCP
2. Connect with IOCR blocks (AR + Input/Output IOCR + ExpectedSubmodule)
3. Parameter phase (PrmBegin / PrmEnd)
4. ApplicationReady
5. Start cyclic data exchange
6. Run for a few seconds, log everything
7. Stop and report

Device: E-T-A at 192.168.1.100, station name "test-eta-device"
Run on Windows VM with: python test_cyclic_hw.py
"""

import logging
import os
import sys
import time
import traceback

# Setup logging FIRST
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s.%(msecs)03d %(levelname)-5s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("cyclic_test")

# Add parent to path for development
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
from profinet.rt import (
    IOCR_TYPE_INPUT,
    IOCR_TYPE_OUTPUT,
    IOCRConfig,
    IODataObject,
)

# ---- Configuration ----
INTERFACE = "Ethernet 3"
DEVICE_NAME = "test-eta-device"
DEVICE_IP = "192.168.1.100"
DEVICE_MAC = "d0:c8:57:e0:1c:2c"

# Use conservative cycle time
SEND_CLOCK_FACTOR = 32  # 1ms base
REDUCTION_RATIO = 128  # 128ms cycle time (very conservative)
WATCHDOG_FACTOR = 10  # 10 * 128ms = 1.28s watchdog
DATA_HOLD_FACTOR = 10

# Device topology from earlier discovery:
# Slot 0 / Subslot 0x0001: DAP (module 0x00003011 / submodule 0x00003010)
# Slot 0 / Subslot 0x8000: Interface (module 0x00003011 / submodule 0x00003011)
# Slot 0 / Subslot 0x8001: Port 1 (module 0x00003011 / submodule 0x00003012)
# Slot 0 / Subslot 0x8002: Port 2 (module 0x00003011 / submodule 0x00003013)
# Slot 1 / Subslot 0x0001: I/O module (module 0x10000000 / submodule 0x20000000)
# Slot 2 / Subslot 0x0001: I/O module (module 0x1000032A / submodule 0x00000001)

RUN_DURATION = 10  # seconds


def hex_dump(data: bytes, prefix: str = "") -> str:
    """Format bytes as hex string."""
    if not data:
        return f"{prefix}(empty)"
    hex_str = " ".join(f"{b:02X}" for b in data)
    return f"{prefix}[{len(data)}B] {hex_str}"


def step(msg: str):
    """Print a step header."""
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}")


def main():
    # ---------------------------------------------------------------
    # Step 1: Discover device
    # ---------------------------------------------------------------
    step("Step 1: Discover device via DCP")

    try:
        src_mac = get_mac(INTERFACE)
        logger.info(f"Controller MAC: {src_mac.hex(':')}")
    except Exception as e:
        logger.error(f"Failed to get MAC for {INTERFACE}: {e}")
        traceback.print_exc()
        sys.exit(1)

    try:
        sock = ethernet_socket(INTERFACE)
        info = get_station_info(sock, src_mac, DEVICE_NAME, timeout_sec=5)
        sock.close()
        logger.info(f"Found device: {info.name} at {info.ip}")
        logger.info(f"  MAC: {info.mac}")
        logger.info(f"  Vendor: 0x{info.vendor_id:04X}, Device: 0x{info.device_id:04X}")
    except Exception as e:
        logger.error(f"Discovery failed: {e}")
        traceback.print_exc()
        sys.exit(1)

    # ---------------------------------------------------------------
    # Step 2: Configure IOCR setup
    # ---------------------------------------------------------------
    step("Step 2: Configure IOCR slots")

    # We need to know the IO data sizes for each slot.
    # Since we don't have the GSD file, we'll try a few approaches:
    #
    # Approach A: DAP only (slot 0) with no IO data - just test the AR setup
    # Approach B: Include slot 1 with guessed IO sizes
    #
    # Start with approach B - include the IO modules.
    # E-T-A devices typically have a few bytes of I/O per module.
    # We'll guess 1 byte input per module for now.
    #
    # The device will tell us in its response if something is wrong.

    iocr_slots = [
        # DAP subslot 1 (device access point)
        IOSlot(
            slot=0,
            subslot=0x0001,
            module_ident=0x00003011,
            submodule_ident=0x00003010,
            input_length=0,
            output_length=0,
        ),
        # Interface submodule (0x8000)
        IOSlot(
            slot=0,
            subslot=0x8000,
            module_ident=0x00003011,
            submodule_ident=0x00003011,
            input_length=0,
            output_length=0,
        ),
        # Port 1 (0x8001)
        IOSlot(
            slot=0,
            subslot=0x8001,
            module_ident=0x00003011,
            submodule_ident=0x00003012,
            input_length=0,
            output_length=0,
        ),
        # Port 2 (0x8002)
        IOSlot(
            slot=0,
            subslot=0x8002,
            module_ident=0x00003011,
            submodule_ident=0x00003013,
            input_length=0,
            output_length=0,
        ),
        # Slot 1: I/O module - try INPUT_OUTPUT with larger sizes
        IOSlot(
            slot=1,
            subslot=0x0001,
            module_ident=0x10000000,
            submodule_ident=0x20000000,
            input_length=2,
            output_length=2,
        ),
    ]

    iocr_setup = IOCRSetup(
        slots=iocr_slots,
        send_clock_factor=SEND_CLOCK_FACTOR,
        reduction_ratio=REDUCTION_RATIO,
        watchdog_factor=WATCHDOG_FACTOR,
        data_hold_factor=DATA_HOLD_FACTOR,
    )

    logger.info(f"Cycle time: {iocr_setup.cycle_time_ms:.1f}ms")
    logger.info(f"Watchdog: {WATCHDOG_FACTOR * iocr_setup.cycle_time_ms:.0f}ms")
    for s in iocr_slots:
        logger.info(
            f"  Slot {s.slot}/0x{s.subslot:04X}: "
            f"module=0x{s.module_ident:08X} sub=0x{s.submodule_ident:08X} "
            f"in={s.input_length}B out={s.output_length}B"
        )

    # ---------------------------------------------------------------
    # Step 3: Connect with IOCR
    # ---------------------------------------------------------------
    step("Step 3: RPC Connect with IOCR")

    rpc = RPCCon(info, timeout=10.0)

    try:
        result = rpc.connect(
            src_mac=src_mac,
            with_alarm_cr=True,  # AlarmCR is mandatory for IO AR per spec
            iocr_setup=iocr_setup,
        )

        if result:
            logger.info("Connect succeeded with IOCR!")
            logger.info(f"  Input Frame ID:  0x{result.input_frame_id:04X}")
            logger.info(f"  Output Frame ID: 0x{result.output_frame_id:04X}")
            logger.info(f"  Has cyclic: {result.has_cyclic}")
        else:
            logger.warning("Connect returned None (no IOCR result)")
            logger.info("Cleaning up and exiting.")
            rpc.close()
            sys.exit(1)

        if not result.has_cyclic:
            logger.error("No cyclic IO established!")
            rpc.close()
            sys.exit(1)

    except Exception as e:
        logger.error(f"Connect failed: {e}")
        traceback.print_exc()
        rpc.close()
        sys.exit(1)

    # ---------------------------------------------------------------
    # Step 4: Parameter phase
    # ---------------------------------------------------------------
    step("Step 4: Parameter phase (PrmBegin/PrmEnd)")

    try:
        logger.info("Sending PrmBegin...")
        resp = rpc.prm_begin()
        logger.info(f"PrmBegin OK (resp={resp})")
    except Exception as e:
        logger.error(f"PrmBegin failed: {e}")
        traceback.print_exc()
        # Don't exit - some devices don't support PrmBegin
        logger.warning("Continuing despite PrmBegin failure...")

    try:
        logger.info("Sending PrmEnd...")
        resp = rpc.prm_end()
        logger.info(f"PrmEnd OK (resp={resp})")
    except Exception as e:
        logger.error(f"PrmEnd failed: {e}")
        traceback.print_exc()
        logger.warning("Continuing despite PrmEnd failure...")

    # ---------------------------------------------------------------
    # Step 5: ApplicationReady
    # ---------------------------------------------------------------
    step("Step 5: ApplicationReady")

    try:
        logger.info("Sending ApplicationReady...")
        resp = rpc.application_ready()
        logger.info(f"ApplicationReady OK (resp={resp})")
    except Exception as e:
        logger.error(f"ApplicationReady failed: {e}")
        traceback.print_exc()
        logger.warning("Continuing to try cyclic exchange anyway...")

    # ---------------------------------------------------------------
    # Step 6: Start cyclic data exchange
    # ---------------------------------------------------------------
    step("Step 6: Cyclic data exchange")

    if not (result.input_frame_id > 0 or result.output_frame_id > 0):
        logger.error("No frame IDs assigned - cannot start cyclic IO")
        rpc.close()
        sys.exit(1)

    dst_mac = bytes.fromhex(info.mac.replace(":", ""))

    # Build IOCRConfig for input (device -> controller)
    # Input objects: slots with input_length > 0
    input_objects = []
    input_frame_offset = 0
    for s in iocr_slots:
        if s.input_length > 0:
            input_objects.append(
                IODataObject(
                    slot=s.slot,
                    subslot=s.subslot,
                    frame_offset=input_frame_offset,
                    data_length=s.input_length,
                    iops_offset=input_frame_offset + s.input_length,
                )
            )
            input_frame_offset += s.input_length + 1  # data + IOPS

    input_iocr = IOCRConfig(
        iocr_type=IOCR_TYPE_INPUT,
        iocr_reference=1,
        frame_id=result.input_frame_id,
        send_clock_factor=SEND_CLOCK_FACTOR,
        reduction_ratio=REDUCTION_RATIO,
        watchdog_factor=WATCHDOG_FACTOR,
        data_length=max(40, input_frame_offset),
        objects=input_objects,
    )

    # Build IOCRConfig for output (controller -> device)
    # Output objects: slots with output_length > 0
    output_objects = []
    output_frame_offset = 0
    for s in iocr_slots:
        if s.output_length > 0:
            output_objects.append(
                IODataObject(
                    slot=s.slot,
                    subslot=s.subslot,
                    frame_offset=output_frame_offset,
                    data_length=s.output_length,
                    iops_offset=output_frame_offset + s.output_length,
                )
            )
            output_frame_offset += s.output_length + 1  # data + IOPS

    output_iocr = IOCRConfig(
        iocr_type=IOCR_TYPE_OUTPUT,
        iocr_reference=2,
        frame_id=result.output_frame_id,
        send_clock_factor=SEND_CLOCK_FACTOR,
        reduction_ratio=REDUCTION_RATIO,
        watchdog_factor=WATCHDOG_FACTOR,
        data_length=max(40, output_frame_offset),
        objects=output_objects,
    )

    logger.info(
        f"Input IOCR: frame_id=0x{input_iocr.frame_id:04X}, "
        f"objects={len(input_objects)}, data_len={input_iocr.data_length}"
    )
    for obj in input_objects:
        logger.info(
            f"  Input obj: slot={obj.slot}/0x{obj.subslot:04X} "
            f"offset={obj.frame_offset} len={obj.data_length} iops={obj.iops_offset}"
        )

    logger.info(
        f"Output IOCR: frame_id=0x{output_iocr.frame_id:04X}, "
        f"objects={len(output_objects)}, data_len={output_iocr.data_length}"
    )
    for obj in output_objects:
        logger.info(
            f"  Output obj: slot={obj.slot}/0x{obj.subslot:04X} "
            f"offset={obj.frame_offset} len={obj.data_length} iops={obj.iops_offset}"
        )

    # Create cyclic controller
    cyclic = CyclicController(
        interface=INTERFACE,
        src_mac=src_mac,
        dst_mac=dst_mac,
        input_iocr=input_iocr,
        output_iocr=output_iocr,
    )

    # Register callbacks
    received_data = []

    def on_input(slot, subslot, data):
        ts = time.time()
        received_data.append((ts, slot, subslot, data))
        if len(received_data) <= 20:  # Log first 20 frames
            logger.info(f"RX: slot={slot}/0x{subslot:04X} {hex_dump(data)}")
        elif len(received_data) % 50 == 0:
            logger.info(
                f"RX: slot={slot}/0x{subslot:04X} {hex_dump(data)} (total: {len(received_data)})"
            )

    def on_timeout():
        logger.warning("WATCHDOG TIMEOUT - no input frame received!")

    def on_error(msg):
        logger.error(f"CYCLIC ERROR: {msg}")

    cyclic.on_input(on_input)
    cyclic.on_timeout(on_timeout)
    cyclic.on_error(on_error)

    # Set initial output data (all zeros with good IOPS)
    for obj in output_objects:
        cyclic.set_output_data(obj.slot, obj.subslot, bytes(obj.data_length))

    # Start!
    logger.info(f"Starting cyclic exchange for {RUN_DURATION}s...")
    cyclic.start()

    start_time = time.time()
    counter = 0
    try:
        while time.time() - start_time < RUN_DURATION:
            time.sleep(1.0)
            counter += 1

            # Print stats every second
            stats = cyclic.stats
            logger.info(
                f"[{counter}s] TX={stats.frames_sent} RX={stats.frames_received} "
                f"Missed={stats.frames_missed} Invalid={stats.frames_invalid} "
                f"Cycle={stats.last_cycle_time_us}us Jitter={stats.max_jitter_us}us"
            )

            # Update output data with a counter byte
            for obj in output_objects:
                data = bytes([counter & 0xFF] * obj.data_length)
                cyclic.set_output_data(obj.slot, obj.subslot, data)

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Error during cyclic exchange: {e}")
        traceback.print_exc()

    # Stop cyclic
    logger.info("Stopping cyclic exchange...")
    cyclic.stop()

    # ---------------------------------------------------------------
    # Step 7: Report
    # ---------------------------------------------------------------
    step("Step 7: Results")

    stats = cyclic.stats
    logger.info(f"Total frames sent:     {stats.frames_sent}")
    logger.info(f"Total frames received: {stats.frames_received}")
    logger.info(f"Frames missed:         {stats.frames_missed}")
    logger.info(f"Frames invalid:        {stats.frames_invalid}")
    logger.info(f"Max jitter:            {stats.max_jitter_us}us")

    if received_data:
        logger.info(f"First input data received at +{received_data[0][0] - start_time:.3f}s")
        logger.info(f"Total unique input updates: {len(received_data)}")
        # Show last few
        for ts, slot, subslot, data in received_data[-5:]:
            logger.info(f"  slot={slot}/0x{subslot:04X}: {hex_dump(data)}")
    else:
        logger.warning("No input data received!")

    # ---------------------------------------------------------------
    # Cleanup
    # ---------------------------------------------------------------
    step("Cleanup: Disconnect")

    try:
        rpc.close()
        logger.info("Disconnected successfully.")
    except Exception as e:
        logger.error(f"Disconnect failed: {e}")
        traceback.print_exc()

    logger.info("Test complete.")


if __name__ == "__main__":
    main()
