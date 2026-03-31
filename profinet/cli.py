"""
PROFINET command-line interface.

"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from collections.abc import Sequence
from typing import Dict, List, Optional, Tuple

from . import dcp, rpc
from .dcp import (
    RESET_MODE_ALL_DATA,
    RESET_MODE_APPLICATION,
    RESET_MODE_COMMUNICATION,
    RESET_MODE_DEVICE,
    RESET_MODE_ENGINEERING,
    RESET_MODE_FACTORY,
)
from .exceptions import (
    DCPDeviceNotFoundError,
    PermissionDeniedError,
    ProfinetError,
    RPCError,
)
from .protocol import PNInM0, PNInM1, PNInM2, PNInM3
from .rpc import IOCRSetup, IOSlot
from .rt import IOCR_TYPE_INPUT, IOCR_TYPE_OUTPUT, IOCRConfig, IODataObject
from .util import ethernet_socket, get_mac, s2mac

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False, debug: bool = False) -> None:
    """Configure logging based on verbosity flags."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


def cmd_discover(args: argparse.Namespace) -> int:
    """Execute discover command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Discovering PROFINET devices on {args.interface}...")
        dcp.send_discover(sock, src)
        responses = dcp.read_response(sock, src, timeout_sec=args.timeout, debug=args.verbose)

        if not responses:
            print("No devices found")
            return 0

        print(f"\nFound {len(responses)} device(s):\n")
        for mac, blocks in responses.items():
            desc = dcp.DCPDeviceDescription(mac, blocks)
            print(desc)
            print()

        return 0
    finally:
        sock.close()


def cmd_get_param(args: argparse.Namespace) -> int:
    """Execute get-param command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        result = dcp.get_param(sock, src, args.target, args.param)
        if result:
            if args.param == "name":
                print(result.decode("utf-8", errors="replace"))
            elif args.param == "ip":
                from .util import s2ip

                print(s2ip(result[:4]))
            else:
                print(result.hex())
        else:
            print(f"Could not read parameter '{args.param}'")
            return 1

        return 0
    finally:
        sock.close()


def cmd_set_param(args: argparse.Namespace) -> int:
    """Execute set-param command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        success = dcp.set_param(sock, src, args.target, args.param, args.value)
        if success:
            print(f"Set {args.param} = {args.value}")
            return 0
        else:
            print(f"Failed to set {args.param}")
            return 1
    finally:
        sock.close()


def cmd_read(args: argparse.Namespace) -> int:
    """Execute read command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Connecting to {args.target}...")
        info = rpc.get_station_info(sock, src, args.target)

        with rpc.RPCCon(info) as conn:
            conn.connect(src)

            idx = int(args.index, 16) if args.index.startswith("0x") else int(args.index)
            iod = conn.read(api=args.api, slot=args.slot, subslot=args.subslot, idx=idx)

            print(f"Read {len(iod.payload)} bytes:")
            print(iod.payload.hex())

        return 0
    finally:
        sock.close()


def cmd_write(args: argparse.Namespace) -> int:
    """Execute write command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Connecting to {args.target}...")
        info = rpc.get_station_info(sock, src, args.target)

        with rpc.RPCCon(info) as conn:
            conn.connect(src)

            idx = int(args.index, 16) if args.index.startswith("0x") else int(args.index)
            data = bytes.fromhex(args.data.replace(" ", ""))
            conn.write(api=args.api, slot=args.slot, subslot=args.subslot, idx=idx, data=data)

            print(f"Wrote {len(data)} bytes to slot={args.slot} subslot={args.subslot} index=0x{idx:04X}")

        return 0
    finally:
        sock.close()


def cmd_read_inm0_filter(args: argparse.Namespace) -> int:
    """Execute read-inm0-filter command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Connecting to {args.target}...")
        info = rpc.get_station_info(sock, src, args.target)

        with rpc.RPCCon(info) as conn:
            conn.connect(src)
            data = conn.read_inm0filter()

            print("\nDevice Topology:")
            for api in data.keys():
                print(f"\nAPI {api}:")
                for slot_number, (module_id, subslots) in data[api].items():
                    print(f"  Slot {slot_number}: Module 0x{module_id:04X}")
                    for subslot_number, submodule_id in subslots.items():
                        print(f"    Subslot {subslot_number}: Submodule 0x{submodule_id:04X}")

        return 0
    finally:
        sock.close()


def cmd_read_inm0(args: argparse.Namespace) -> int:
    """Execute read-inm0 command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Connecting to {args.target}...")
        info = rpc.get_station_info(sock, src, args.target)

        with rpc.RPCCon(info) as conn:
            conn.connect(src)
            iod = conn.read(api=args.api, slot=args.slot, subslot=args.subslot, idx=PNInM0.IDX)

            if iod.payload:
                im0 = PNInM0(iod.payload)
                print(im0)
            else:
                print("No IM0 data available")

        return 0
    finally:
        sock.close()


def cmd_read_inm1(args: argparse.Namespace) -> int:
    """Execute read-inm1 command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Connecting to {args.target}...")
        info = rpc.get_station_info(sock, src, args.target)

        with rpc.RPCCon(info) as conn:
            conn.connect(src)
            iod = conn.read(api=args.api, slot=args.slot, subslot=args.subslot, idx=PNInM1.IDX)

            if iod.payload:
                im1 = PNInM1(iod.payload)
                print(im1)
            else:
                print("No IM1 data available")

        return 0
    finally:
        sock.close()


def cmd_read_inm2(args: argparse.Namespace) -> int:
    """Execute read-inm2 command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Connecting to {args.target}...")
        info = rpc.get_station_info(sock, src, args.target)

        with rpc.RPCCon(info) as conn:
            conn.connect(src)
            iod = conn.read(api=args.api, slot=args.slot, subslot=args.subslot, idx=PNInM2.IDX)

            if iod.payload:
                im2 = PNInM2(iod.payload)
                print(im2)
            else:
                print("No IM2 data available")

        return 0
    finally:
        sock.close()


def cmd_read_inm3(args: argparse.Namespace) -> int:
    """Execute read-inm3 command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Connecting to {args.target}...")
        info = rpc.get_station_info(sock, src, args.target)

        with rpc.RPCCon(info) as conn:
            conn.connect(src)
            iod = conn.read(api=args.api, slot=args.slot, subslot=args.subslot, idx=PNInM3.IDX)

            if iod.payload:
                im3 = PNInM3(iod.payload)
                print(im3)
            else:
                print("No IM3 data available")

        return 0
    finally:
        sock.close()


def cmd_set_ip(args: argparse.Namespace) -> int:
    """Execute set-ip command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Setting IP {args.ip} on {args.target}...")
        success = dcp.set_ip(
            sock,
            src,
            args.target,
            args.ip,
            args.netmask,
            args.gateway,
            permanent=args.permanent,
        )
        if success:
            print(f"Set IP={args.ip} netmask={args.netmask} gateway={args.gateway}")
            return 0
        else:
            print("Failed to set IP (timeout)")
            return 1
    finally:
        sock.close()


def cmd_signal(args: argparse.Namespace) -> int:
    """Execute signal command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        print(f"Signalling device {args.target}...")
        success = dcp.signal_device(sock, src, args.target)
        if success:
            print("Device LED flash triggered")
            return 0
        else:
            print("Failed to signal device (timeout)")
            return 1
    finally:
        sock.close()


RESET_MODES = {
    "communication": RESET_MODE_COMMUNICATION,
    "application": RESET_MODE_APPLICATION,
    "engineering": RESET_MODE_ENGINEERING,
    "all-data": RESET_MODE_ALL_DATA,
    "device": RESET_MODE_DEVICE,
    "factory": RESET_MODE_FACTORY,
}


def cmd_reset(args: argparse.Namespace) -> int:
    """Execute reset command."""
    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)
        mode = RESET_MODES[args.mode]

        print(f"Resetting device {args.target} (mode: {args.mode})...")
        success = dcp.reset_to_factory(sock, src, args.target, mode=mode)
        if success:
            print("Reset command acknowledged")
            return 0
        else:
            print("Failed to reset device (timeout)")
            return 1
    finally:
        sock.close()


def _build_iocr_configs(
    slots: List[IOSlot],
    input_frame_id: int,
    output_frame_id: int,
    send_clock_factor: int,
    reduction_ratio: int,
    watchdog_factor: int = 6,
) -> Tuple[IOCRConfig, IOCRConfig]:
    """Build IOCRConfig pair from IOSlots and ConnectResult frame IDs.

    Mirrors the frame_offset calculation in RPCCon._build_iocr_block().
    """

    def _build_one(iocr_type: int, frame_id: int) -> IOCRConfig:
        objects: List[IODataObject] = []
        frame_offset = 0

        # IODataObjects for slots with data in this direction
        for s in slots:
            data_len = s.input_length if iocr_type == IOCR_TYPE_INPUT else s.output_length
            if data_len > 0:
                objects.append(
                    IODataObject(
                        slot=s.slot,
                        subslot=s.subslot,
                        frame_offset=frame_offset,
                        data_length=data_len,
                        iops_offset=frame_offset + data_len,
                    )
                )
                frame_offset += data_len + 1  # data + IOPS

        # IOCS entries for slots without data in this direction
        for s in slots:
            data_len = s.input_length if iocr_type == IOCR_TYPE_INPUT else s.output_length
            if data_len == 0:
                frame_offset += 1  # IOCS byte

        data_length = max(40, frame_offset)

        return IOCRConfig(
            iocr_type=iocr_type,
            iocr_reference=1 if iocr_type == IOCR_TYPE_INPUT else 2,
            frame_id=frame_id,
            send_clock_factor=send_clock_factor,
            reduction_ratio=reduction_ratio,
            watchdog_factor=watchdog_factor,
            data_length=data_length,
            objects=objects,
        )

    input_iocr = _build_one(IOCR_TYPE_INPUT, input_frame_id)
    output_iocr = _build_one(IOCR_TYPE_OUTPUT, output_frame_id)
    return input_iocr, output_iocr


def cmd_cyclic(args: argparse.Namespace) -> int:
    """Execute cyclic IO command."""
    from .cyclic import CyclicController
    from .gsdml import load_gsdml

    sock = ethernet_socket(args.interface, 3)
    try:
        src = get_mac(args.interface)

        # Step 1: Resolve device
        info = rpc.get_station_info(sock, src, args.target)
        print(f"Connecting to {args.target} ({info.ip})...")

        # Step 2: Acyclic connect to discover slots
        conn = rpc.RPCCon(info)
        conn.connect(src)

        print("Discovering slots...", end=" ")
        device_slots = conn.discover_slots()
        print(f"{len(device_slots)} entries")

        # Step 3: Load GSDML and match against device slots
        gsdml_device = load_gsdml(args.gsdml)

        # Parse --submodule overrides: slot:subslot:submodule_id
        sub_assign: Dict[int, Dict[int, str]] = {}
        if args.submodule:
            for spec in args.submodule:
                parts = spec.split(":", 2)
                if len(parts) != 3:
                    print(
                        f"Error: invalid --submodule format '{spec}', expected slot:subslot:submodule_id"
                    )
                    conn.close()
                    return 1
                slot_n, subslot_n, sub_id = int(parts[0]), int(parts[1]), parts[2]
                sub_assign.setdefault(slot_n, {})[subslot_n] = sub_id

        io_slots = gsdml_device.build_io_slots_from_device(device_slots)

        print("Matching against GSDML...")
        total_in = 0
        total_out = 0
        for s in io_slots:
            if s.input_length > 0 or s.output_length > 0:
                io_desc = []
                if s.input_length > 0:
                    io_desc.append(f"{s.input_length}B in")
                if s.output_length > 0:
                    io_desc.append(f"{s.output_length}B out")
                print(f"  slot={s.slot} sub={s.subslot}: {', '.join(io_desc)}")
            total_in += s.input_length
            total_out += s.output_length
        print(f"Total: {total_in}B input, {total_out}B output")

        # Step 4: Disconnect acyclic, reconnect with IOCR
        # Close old connection and wait for device to process the Release
        # before rebinding the RPC port, otherwise the stale Release response
        # gets consumed as the new Connect response.
        conn.close()
        time.sleep(0.5)

        cycle_ms = args.cycle_ms
        send_clock_factor = 32
        reduction_ratio = cycle_ms

        setup = IOCRSetup(
            slots=io_slots,
            send_clock_factor=send_clock_factor,
            reduction_ratio=reduction_ratio,
            watchdog_factor=6,
            data_hold_factor=6,
        )

        conn = rpc.RPCCon(info)

        # Drain any stale UDP packets (Release response from previous AR)
        conn._socket.settimeout(0.1)
        try:
            while True:
                conn._socket.recvfrom(4096)
        except (TimeoutError, OSError):
            pass
        conn._socket.settimeout(conn.timeout)

        result = conn.connect(src, iocr_setup=setup)

        if not result or not result.has_cyclic:
            print("Error: cyclic IO not established by device")
            conn.close()
            return 1

        # Step 5: Parameter phase and ApplicationReady
        # After CONNECT with IOCR, the PRM phase is implicit (no PrmBegin needed).
        # PrmBegin is only for re-parameterization of an already-running AR.
        print(f"\nCyclic IO ({cycle_ms}ms cycle)...")

        conn.prm_end()
        print("  PrmEnd OK")

        conn.application_ready()
        print("  ApplicationReady OK")
        print(
            f"  Input frame: 0x{result.input_frame_id:04X}, Output frame: 0x{result.output_frame_id:04X}"
        )

        # Step 6: Build IOCRConfigs and start cyclic controller
        input_iocr, output_iocr = _build_iocr_configs(
            io_slots,
            result.input_frame_id,
            result.output_frame_id,
            send_clock_factor,
            reduction_ratio,
        )

        # src from get_mac is already bytes; dst_mac from info.mac is string
        dst_mac = s2mac(info.mac)

        cyclic = CyclicController(
            interface=args.interface,
            src_mac=src,
            dst_mac=dst_mac,
            input_iocr=input_iocr,
            output_iocr=output_iocr,
        )

        # Collect input data for display
        input_slots = [(s.slot, s.subslot) for s in io_slots if s.input_length > 0]
        latest_input: Dict[Tuple[int, int], bytes] = {}

        def on_input(slot: int, subslot: int, data: bytes) -> None:
            latest_input[(slot, subslot)] = data

        cyclic.on_input(on_input)
        cyclic.start()

        print("\nRunning (Ctrl+C to stop)")
        start_time = time.monotonic()
        try:
            while True:
                time.sleep(1.0)
                elapsed = time.monotonic() - start_time

                if args.duration > 0 and elapsed >= args.duration:
                    break

                # Format input data display
                io_parts = []
                for key in input_slots:
                    data = latest_input.get(key)
                    if data:
                        io_parts.append(f"{key[0]}:{key[1]}={data.hex()}")
                    else:
                        io_parts.append(f"{key[0]}:{key[1]}=--")
                data_str = " ".join(io_parts)

                print(
                    f"[{elapsed:5.1f}s] {data_str} | "
                    f"TX={cyclic.stats.frames_sent} RX={cyclic.stats.frames_received}"
                )

        except KeyboardInterrupt:
            pass

        cyclic.stop()
        print(
            f"\nStopped. TX={cyclic.stats.frames_sent} "
            f"RX={cyclic.stats.frames_received} "
            f"missed={cyclic.stats.frames_missed}"
        )
        conn.close()
        return 0

    finally:
        sock.close()


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog="profinet",
        description="PROFINET IO-Controller CLI",
        epilog="https://github.com/f0rw4rd/profinet-py",
    )

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        metavar="IFACE",
        help="Network interface to use",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Discovery timeout in seconds (default: 10)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # discover
    sub = subparsers.add_parser("discover", help="Discover PROFINET devices")
    sub.set_defaults(func=cmd_discover)

    # get-param
    sub = subparsers.add_parser("get-param", help="Read device parameter")
    sub.add_argument("target", metavar="MAC", help="Device MAC address (e.g. aa:bb:cc:dd:ee:ff)")
    sub.add_argument("param", choices=["name", "ip"], help="Parameter to read")
    sub.set_defaults(func=cmd_get_param)

    # set-param
    sub = subparsers.add_parser("set-param", help="Write device parameter")
    sub.add_argument("target", metavar="MAC", help="Device MAC address (e.g. aa:bb:cc:dd:ee:ff)")
    sub.add_argument("param", choices=["name", "ip"], help="Parameter to write")
    sub.add_argument("value", help="New value")
    sub.set_defaults(func=cmd_set_param)

    # read
    sub = subparsers.add_parser("read", help="Read data record")
    sub.add_argument("target", metavar="NAME", help="Station name (e.g. my-device)")
    sub.add_argument("--api", type=int, default=0, help="API (default: 0)")
    sub.add_argument("--slot", type=int, required=True, help="Slot number")
    sub.add_argument("--subslot", type=int, required=True, help="Subslot number")
    sub.add_argument("--index", required=True, help="Record index (hex with 0x prefix)")
    sub.set_defaults(func=cmd_read)

    # write
    sub = subparsers.add_parser("write", help="Write data record")
    sub.add_argument("target", metavar="NAME", help="Station name (e.g. my-device)")
    sub.add_argument("--api", type=int, default=0, help="API (default: 0)")
    sub.add_argument("--slot", type=int, required=True, help="Slot number")
    sub.add_argument("--subslot", type=int, required=True, help="Subslot number")
    sub.add_argument("--index", required=True, help="Record index (hex with 0x prefix, e.g. 0xAFF1)")
    sub.add_argument("data", metavar="HEX", help="Data to write as hex string (e.g. deadbeef)")
    sub.set_defaults(func=cmd_write)

    # read-inm0-filter
    sub = subparsers.add_parser("read-inm0-filter", help="Read device topology")
    sub.add_argument("target", metavar="NAME", help="Station name (e.g. my-device)")
    sub.set_defaults(func=cmd_read_inm0_filter)

    # read-inm0
    sub = subparsers.add_parser("read-inm0", help="Read IM0 identification data")
    sub.add_argument("target", metavar="NAME", help="Station name (e.g. my-device)")
    sub.add_argument("--api", type=int, default=0, help="API (default: 0)")
    sub.add_argument("--slot", type=int, default=0, help="Slot number (default: 0)")
    sub.add_argument("--subslot", type=int, default=1, help="Subslot number (default: 1)")
    sub.set_defaults(func=cmd_read_inm0)

    # read-inm1
    sub = subparsers.add_parser("read-inm1", help="Read IM1 tag data")
    sub.add_argument("target", metavar="NAME", help="Station name (e.g. my-device)")
    sub.add_argument("--api", type=int, default=0, help="API (default: 0)")
    sub.add_argument("--slot", type=int, default=0, help="Slot number (default: 0)")
    sub.add_argument("--subslot", type=int, default=1, help="Subslot number (default: 1)")
    sub.set_defaults(func=cmd_read_inm1)

    # read-inm2
    sub = subparsers.add_parser("read-inm2", help="Read IM2 date data")
    sub.add_argument("target", metavar="NAME", help="Station name (e.g. my-device)")
    sub.add_argument("--api", type=int, default=0, help="API (default: 0)")
    sub.add_argument("--slot", type=int, default=0, help="Slot number (default: 0)")
    sub.add_argument("--subslot", type=int, default=1, help="Subslot number (default: 1)")
    sub.set_defaults(func=cmd_read_inm2)

    # read-inm3
    sub = subparsers.add_parser("read-inm3", help="Read IM3 descriptor data")
    sub.add_argument("target", metavar="NAME", help="Station name (e.g. my-device)")
    sub.add_argument("--api", type=int, default=0, help="API (default: 0)")
    sub.add_argument("--slot", type=int, default=0, help="Slot number (default: 0)")
    sub.add_argument("--subslot", type=int, default=1, help="Subslot number (default: 1)")
    sub.set_defaults(func=cmd_read_inm3)

    # set-ip
    sub = subparsers.add_parser("set-ip", help="Set device IP configuration via DCP")
    sub.add_argument("target", metavar="MAC", help="Device MAC address (e.g. aa:bb:cc:dd:ee:ff)")
    sub.add_argument("ip", help="IP address")
    sub.add_argument("netmask", help="Subnet mask")
    sub.add_argument("gateway", help="Gateway address")
    sub.add_argument("--permanent", action="store_true", help="Save IP permanently")
    sub.set_defaults(func=cmd_set_ip)

    # signal
    sub = subparsers.add_parser("signal", help="Flash device LEDs")
    sub.add_argument("target", metavar="MAC", help="Device MAC address (e.g. aa:bb:cc:dd:ee:ff)")
    sub.set_defaults(func=cmd_signal)

    # reset
    sub = subparsers.add_parser("reset", help="Reset device to factory settings")
    sub.add_argument("target", metavar="MAC", help="Device MAC address (e.g. aa:bb:cc:dd:ee:ff)")
    sub.add_argument(
        "--mode",
        choices=["communication", "application", "engineering", "all-data", "device", "factory"],
        default="factory",
        help="Reset mode (default: factory)",
    )
    sub.set_defaults(func=cmd_reset)

    # cyclic
    sub = subparsers.add_parser("cyclic", help="Monitor cyclic IO using GSDML")
    sub.add_argument("target", metavar="NAME", help="Station name (e.g. my-device)")
    sub.add_argument("--gsdml", required=True, help="Path to GSDML XML file")
    sub.add_argument("--cycle-ms", type=int, default=32, help="Cycle time in ms (default: 32)")
    sub.add_argument("--duration", type=int, default=0, help="Seconds to run (0 = until Ctrl+C)")
    sub.add_argument(
        "--submodule",
        action="append",
        metavar="SLOT:SUBSLOT:ID",
        help="Submodule override as slot:subslot:submodule_id (repeatable)",
    )
    sub.set_defaults(func=cmd_cyclic)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    setup_logging(args.verbose, args.debug)

    try:
        return args.func(args)
    except PermissionDeniedError:
        print("Error: Root privileges required for raw socket access", file=sys.stderr)
        return 1
    except DCPDeviceNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except RPCError as e:
        print(f"RPC Error: {e}", file=sys.stderr)
        return 1
    except ProfinetError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted")
        return 130
    except Exception as e:
        logger.exception("Unexpected error")
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
