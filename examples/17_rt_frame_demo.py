#!/usr/bin/env python3
"""
RT Frame Demo.

Demonstrates PROFINET Real-Time (RT) frame structures without
requiring a full cyclic IO connection.

This example shows:
- Building RT frames
- Parsing RT frames
- Working with IOCRConfig and CyclicDataBuilder
- Understanding frame structure

No device connection needed - runs offline.
"""

from profinet import (
    IOCR_TYPE_INPUT,
    IOCR_TYPE_OUTPUT,
    IOXS_GOOD,
    CyclicDataBuilder,
    IOCRConfig,
    IODataObject,
    RTFrame,
)
from profinet.rt import (
    DATA_STATUS_PROVIDER_RUN,
    DATA_STATUS_STATE,
    DATA_STATUS_STATION_OK,
    DATA_STATUS_VALID,
    build_ethernet_frame,
    parse_ethernet_frame,
)


def demo_rt_frame():
    """Demonstrate RTFrame construction and parsing."""
    print("=" * 60)
    print("RTFrame Demo")
    print("=" * 60)

    # Create a simple RT frame
    payload = b"\x01\x02\x03\x04\x80"  # 4 bytes data + IOPS
    frame = RTFrame(
        frame_id=0xC000,
        cycle_counter=100,
        data_status=DATA_STATUS_VALID | DATA_STATUS_PROVIDER_RUN | DATA_STATUS_STATION_OK,
        transfer_status=0x00,
        payload=payload,
    )

    print(f"Created frame: {frame}")
    print(f"  Frame ID: 0x{frame.frame_id:04X}")
    print(f"  Cycle counter: {frame.cycle_counter}")
    print(f"  Is valid: {frame.is_valid}")
    print(f"  Is running: {frame.is_running}")
    print(f"  Is OK: {frame.is_ok}")

    # Serialize to bytes
    raw = frame.to_bytes()
    print(f"\nSerialized ({len(raw)} bytes):")
    print(f"  {raw.hex()}")

    # Parse it back
    parsed = RTFrame.from_bytes(raw)
    print(f"\nParsed back: {parsed}")
    print(f"  Payload matches: {parsed.payload == payload}")


def demo_iocr_config():
    """Demonstrate IOCR configuration."""
    print("\n" + "=" * 60)
    print("IOCRConfig Demo")
    print("=" * 60)

    # Create output IOCR config (controller -> device)
    output_iocr = IOCRConfig(
        iocr_type=IOCR_TYPE_OUTPUT,
        iocr_reference=1,
        frame_id=0xC000,
        send_clock_factor=32,  # 1ms base
        reduction_ratio=8,  # Every 8 cycles
        watchdog_factor=3,
        data_length=48,
        objects=[
            IODataObject(
                slot=1, subslot=1, frame_offset=0, data_length=8, iops_offset=8, iocs_offset=0
            ),
            IODataObject(
                slot=2, subslot=1, frame_offset=9, data_length=4, iops_offset=13, iocs_offset=0
            ),
        ],
    )

    print("Output IOCR (Controller -> Device):")
    print(f"  Frame ID: 0x{output_iocr.frame_id:04X}")
    print(f"  Cycle time: {output_iocr.cycle_time_ms:.1f} ms")
    print(f"  Watchdog: {output_iocr.watchdog_time_us / 1000:.1f} ms")
    print(f"  Data length: {output_iocr.data_length} bytes")
    print(f"  IO objects: {len(output_iocr.objects)}")

    # Create input IOCR config (device -> controller)
    input_iocr = IOCRConfig(
        iocr_type=IOCR_TYPE_INPUT,
        iocr_reference=2,
        frame_id=0xC001,
        send_clock_factor=32,
        reduction_ratio=8,
        data_length=32,
        objects=[
            IODataObject(
                slot=0, subslot=1, frame_offset=0, data_length=4, iops_offset=4, iocs_offset=5
            ),
        ],
    )

    print("\nInput IOCR (Device -> Controller):")
    print(f"  Frame ID: 0x{input_iocr.frame_id:04X}")
    print(f"  Is input: {input_iocr.is_input}")


def demo_cyclic_data_builder():
    """Demonstrate CyclicDataBuilder payload construction."""
    print("\n" + "=" * 60)
    print("CyclicDataBuilder Demo")
    print("=" * 60)

    config = IOCRConfig(
        iocr_type=IOCR_TYPE_OUTPUT,
        iocr_reference=1,
        frame_id=0xC000,
        data_length=48,
        objects=[
            IODataObject(slot=1, subslot=1, frame_offset=0, data_length=8, iops_offset=8),
            IODataObject(slot=2, subslot=1, frame_offset=10, data_length=4, iops_offset=14),
        ],
    )

    builder = CyclicDataBuilder(config)

    # Set process data for slot 1
    data1 = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
    builder.set_data(1, 1, data1)
    builder.set_iops(1, 1, IOXS_GOOD)
    print(f"Set slot 1 data: {data1.hex()}")

    # Set process data for slot 2
    data2 = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    builder.set_data(2, 1, data2)
    builder.set_iops(2, 1, IOXS_GOOD)
    print(f"Set slot 2 data: {data2.hex()}")

    # Swap write buffer to send buffer, then build payload
    builder.swap()
    payload = builder.build()
    print(f"\nBuilt C_SDU payload ({len(payload)} bytes):")
    print(f"  Offset 0-7 (slot 1 data): {payload[0:8].hex()}")
    print(f"  Offset 8 (slot 1 IOPS): 0x{payload[8]:02X}")
    print(f"  Offset 10-13 (slot 2 data): {payload[10:14].hex()}")
    print(f"  Offset 14 (slot 2 IOPS): 0x{payload[14]:02X}")

    # Verify we can read it back
    retrieved = builder.get_data(1, 1)
    print(f"\nRetrieved slot 1 data: {retrieved.hex()}")
    print(f"  Matches: {retrieved == data1}")


def demo_ethernet_frame():
    """Demonstrate complete Ethernet frame building."""
    print("\n" + "=" * 60)
    print("Ethernet Frame Demo")
    print("=" * 60)

    dst_mac = b"\xd0\xc8\x57\xe0\x1c\x2c"  # Device MAC
    src_mac = b"\x00\x11\x22\x33\x44\x55"  # Controller MAC

    rt_frame = RTFrame(
        frame_id=0xC000,
        cycle_counter=42,
        data_status=DATA_STATUS_VALID
        | DATA_STATUS_PROVIDER_RUN
        | DATA_STATUS_STATION_OK
        | DATA_STATUS_STATE,
        transfer_status=0x00,
        payload=b"\x01\x02\x03\x04" + bytes([IOXS_GOOD]),
    )

    eth_frame = build_ethernet_frame(dst_mac, src_mac, rt_frame)

    print(f"Built Ethernet frame ({len(eth_frame)} bytes):")
    print(f"  Dst MAC: {':'.join(f'{b:02x}' for b in eth_frame[0:6])}")
    print(f"  Src MAC: {':'.join(f'{b:02x}' for b in eth_frame[6:12])}")
    print(f"  EtherType: 0x{eth_frame[12]:02X}{eth_frame[13]:02X}")
    print(f"  Frame ID: 0x{eth_frame[14]:02X}{eth_frame[15]:02X}")

    # Parse it back
    parsed = parse_ethernet_frame(eth_frame)
    print("\nParsed from Ethernet frame:")
    print(f"  {parsed}")
    print(f"  Cycle counter matches: {parsed.cycle_counter == 42}")


def demo_timing_calculations():
    """Demonstrate timing calculations."""
    print("\n" + "=" * 60)
    print("Timing Calculations Demo")
    print("=" * 60)

    print("Cycle time examples (send_clock_factor * reduction_ratio * 31.25µs):")
    print()

    examples = [
        (1, 1, "31.25µs (hardware only)"),
        (32, 1, "1ms (Python minimum)"),
        (32, 4, "4ms"),
        (32, 8, "8ms"),
        (32, 32, "32ms"),
        (32, 128, "128ms"),
    ]

    for scf, rr, note in examples:
        config = IOCRConfig(IOCR_TYPE_OUTPUT, 1, 0xC000, scf, rr)
        print(f"  SCF={scf:3d}, RR={rr:3d} => {config.cycle_time_ms:7.2f}ms  ({note})")

    print()
    print("Note: Python cannot reliably achieve cycle times below 1ms due to GIL.")


def main():
    """Run all demos."""
    demo_rt_frame()
    demo_iocr_config()
    demo_cyclic_data_builder()
    demo_ethernet_frame()
    demo_timing_calculations()

    print("\n" + "=" * 60)
    print("All demos complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
