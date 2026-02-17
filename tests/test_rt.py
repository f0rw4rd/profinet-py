"""Tests for profinet.rt module (Real-Time frame handling)."""

import pytest

from profinet.rt import (
    DATA_STATUS_PROVIDER_RUN,
    DATA_STATUS_STATE,
    DATA_STATUS_STATION_OK,
    DATA_STATUS_VALID,
    IOCR_TYPE_INPUT,
    IOCR_TYPE_OUTPUT,
    IOXS_GOOD,
    CyclicDataBuilder,
    IOCRConfig,
    IODataObject,
    RTFrame,
    build_ethernet_frame,
    parse_ethernet_frame,
)


class TestRTFrame:
    """Test RTFrame serialization and deserialization."""

    def test_from_bytes_minimal(self):
        """Test parsing minimal RT frame."""
        # Frame ID + 2 byte payload + cycle(2) + status(2)
        data = b"\xc0\x00\x01\x02\x12\x34\xa4\x00"
        frame = RTFrame.from_bytes(data)

        assert frame.frame_id == 0xC000
        assert frame.payload == b"\x01\x02"
        assert frame.cycle_counter == 0x1234
        assert frame.data_status == 0xA4
        assert frame.transfer_status == 0x00

    def test_from_bytes_typical(self):
        """Test parsing typical sized RT frame."""
        # 40-byte payload (minimum C_SDU size)
        payload = bytes(40)
        data = (
            b"\xc0\x01"  # Frame ID
            + payload  # C_SDU
            + b"\x00\x42"  # Cycle counter
            + b"\xa4\x00"  # Status bytes
        )
        frame = RTFrame.from_bytes(data)

        assert frame.frame_id == 0xC001
        assert len(frame.payload) == 40
        assert frame.cycle_counter == 0x0042

    def test_to_bytes_roundtrip(self):
        """Test serialization and deserialization match."""
        original = RTFrame(
            frame_id=0xC000,
            cycle_counter=0x1234,
            data_status=0xA4,
            transfer_status=0x00,
            payload=b"\x01\x02\x03\x04",
        )

        data = original.to_bytes()
        parsed = RTFrame.from_bytes(data)

        assert parsed.frame_id == original.frame_id
        assert parsed.cycle_counter == original.cycle_counter
        assert parsed.data_status == original.data_status
        assert parsed.transfer_status == original.transfer_status
        assert parsed.payload == original.payload

    def test_is_valid(self):
        """Test is_valid property."""
        frame_valid = RTFrame(0xC000, 0, DATA_STATUS_VALID, 0, b"")
        frame_invalid = RTFrame(0xC000, 0, 0x00, 0, b"")

        assert frame_valid.is_valid
        assert not frame_invalid.is_valid

    def test_is_running(self):
        """Test is_running property."""
        frame_run = RTFrame(0xC000, 0, DATA_STATUS_PROVIDER_RUN, 0, b"")
        frame_stop = RTFrame(0xC000, 0, 0x00, 0, b"")

        assert frame_run.is_running
        assert not frame_stop.is_running

    def test_is_ok(self):
        """Test is_ok property."""
        frame_ok = RTFrame(0xC000, 0, DATA_STATUS_STATION_OK, 0, b"")
        frame_problem = RTFrame(0xC000, 0, 0x00, 0, b"")

        assert frame_ok.is_ok
        assert not frame_problem.is_ok

    def test_is_primary(self):
        """Test is_primary property."""
        frame_primary = RTFrame(0xC000, 0, DATA_STATUS_STATE, 0, b"")
        frame_backup = RTFrame(0xC000, 0, 0x00, 0, b"")

        assert frame_primary.is_primary
        assert not frame_backup.is_primary

    def test_combined_status(self):
        """Test combined status flags."""
        status = (
            DATA_STATUS_VALID
            | DATA_STATUS_PROVIDER_RUN
            | DATA_STATUS_STATION_OK
            | DATA_STATUS_STATE
        )
        frame = RTFrame(0xC000, 0, status, 0, b"")

        assert frame.is_valid
        assert frame.is_running
        assert frame.is_ok
        assert frame.is_primary

    def test_from_bytes_too_short(self):
        """Test parsing fails for too-short data."""
        with pytest.raises(ValueError, match="too short"):
            RTFrame.from_bytes(b"\xc0\x00\x00")

    def test_repr(self):
        """Test string representation."""
        frame = RTFrame(
            frame_id=0xC000,
            cycle_counter=100,
            data_status=DATA_STATUS_VALID | DATA_STATUS_PROVIDER_RUN,
            transfer_status=0,
            payload=b"\x00" * 10,
        )
        s = repr(frame)
        assert "0xC000" in s
        assert "VALID" in s
        assert "RUN" in s
        assert "10B" in s


class TestIOCRConfig:
    """Test IOCRConfig configuration class."""

    def test_cycle_time_calculation(self):
        """Test cycle time calculation."""
        config = IOCRConfig(
            iocr_type=IOCR_TYPE_OUTPUT,
            iocr_reference=1,
            frame_id=0xC000,
            send_clock_factor=32,  # 1ms base
            reduction_ratio=1,  # Every cycle
        )
        # 32 * 1 * 31.25µs = 1000µs = 1ms
        assert config.cycle_time_us == 1000
        assert config.cycle_time_ms == 1.0

    def test_cycle_time_8ms(self):
        """Test 8ms cycle time."""
        config = IOCRConfig(
            iocr_type=IOCR_TYPE_OUTPUT,
            iocr_reference=1,
            frame_id=0xC000,
            send_clock_factor=32,
            reduction_ratio=8,
        )
        assert config.cycle_time_us == 8000
        assert config.cycle_time_ms == 8.0

    def test_watchdog_time(self):
        """Test watchdog timeout calculation."""
        config = IOCRConfig(
            iocr_type=IOCR_TYPE_INPUT,
            iocr_reference=1,
            frame_id=0xC001,
            send_clock_factor=32,
            reduction_ratio=8,
            watchdog_factor=3,
        )
        # 3 * 8000µs = 24000µs
        assert config.watchdog_time_us == 24000

    def test_is_input(self):
        """Test is_input property."""
        config_in = IOCRConfig(IOCR_TYPE_INPUT, 1, 0xC000)
        config_out = IOCRConfig(IOCR_TYPE_OUTPUT, 1, 0xC000)

        assert config_in.is_input
        assert not config_in.is_output
        assert config_out.is_output
        assert not config_out.is_input


class TestCyclicDataBuilder:
    """Test CyclicDataBuilder payload construction with double-buffering."""

    def test_set_and_get_data(self):
        """Test setting and getting process data."""
        config = IOCRConfig(
            iocr_type=IOCR_TYPE_OUTPUT,
            iocr_reference=1,
            frame_id=0xC000,
            data_length=48,
            objects=[
                IODataObject(slot=1, subslot=1, frame_offset=0, data_length=8, iops_offset=8),
            ],
        )
        builder = CyclicDataBuilder(config)

        test_data = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        builder.set_data(1, 1, test_data)
        result = builder.get_data(1, 1)

        assert result == test_data

    def test_set_iops(self):
        """Test setting IOPS byte."""
        config = IOCRConfig(
            iocr_type=IOCR_TYPE_OUTPUT,
            iocr_reference=1,
            frame_id=0xC000,
            data_length=16,
            objects=[
                IODataObject(slot=1, subslot=1, frame_offset=0, data_length=4, iops_offset=4),
            ],
        )
        builder = CyclicDataBuilder(config)
        builder.set_iops(1, 1, IOXS_GOOD)
        builder.swap()
        payload = builder.build()

        assert payload[4] == IOXS_GOOD

    def test_build_returns_correct_length(self):
        """Test build returns configured data length."""
        config = IOCRConfig(
            iocr_type=IOCR_TYPE_OUTPUT,
            iocr_reference=1,
            frame_id=0xC000,
            data_length=64,
            objects=[],
        )
        builder = CyclicDataBuilder(config)
        payload = builder.build()

        assert len(payload) == 64

    def test_unknown_slot_raises(self):
        """Test setting data for unknown slot raises error."""
        config = IOCRConfig(
            iocr_type=IOCR_TYPE_OUTPUT,
            iocr_reference=1,
            frame_id=0xC000,
            data_length=48,
            objects=[],
        )
        builder = CyclicDataBuilder(config)

        with pytest.raises(ValueError, match="Unknown slot/subslot"):
            builder.set_data(99, 99, b"\x00")

    def test_set_all_iops(self):
        """Test setting IOPS for all objects."""
        config = IOCRConfig(
            iocr_type=IOCR_TYPE_OUTPUT,
            iocr_reference=1,
            frame_id=0xC000,
            data_length=32,
            objects=[
                IODataObject(slot=0, subslot=1, frame_offset=0, data_length=4, iops_offset=4),
                IODataObject(slot=1, subslot=1, frame_offset=8, data_length=4, iops_offset=12),
            ],
        )
        builder = CyclicDataBuilder(config)
        builder.set_all_iops(IOXS_GOOD)
        builder.swap()
        payload = builder.build()

        assert payload[4] == IOXS_GOOD
        assert payload[12] == IOXS_GOOD

    def test_clear(self):
        """Test clearing all data."""
        config = IOCRConfig(
            iocr_type=IOCR_TYPE_OUTPUT,
            iocr_reference=1,
            frame_id=0xC000,
            data_length=16,
            objects=[
                IODataObject(slot=1, subslot=1, frame_offset=0, data_length=8, iops_offset=8),
            ],
        )
        builder = CyclicDataBuilder(config)
        builder.set_data(1, 1, b"\xff" * 8)
        builder.clear()
        builder.swap()
        payload = builder.build()

        assert payload == b"\x00" * 16

    def test_load(self):
        """Test loading received payload."""
        config = IOCRConfig(
            iocr_type=IOCR_TYPE_INPUT,
            iocr_reference=1,
            frame_id=0xC001,
            data_length=16,
            objects=[
                IODataObject(slot=1, subslot=1, frame_offset=0, data_length=8, iops_offset=8),
            ],
        )
        builder = CyclicDataBuilder(config)
        received = b"\x11\x22\x33\x44\x55\x66\x77\x88\x80" + b"\x00" * 7
        builder.load(received)

        assert builder.get_data(1, 1) == b"\x11\x22\x33\x44\x55\x66\x77\x88"

    def test_double_buffer_isolation(self):
        """Write buffer changes don't affect send buffer until swap."""
        config = IOCRConfig(
            iocr_type=IOCR_TYPE_OUTPUT,
            iocr_reference=1,
            frame_id=0xC000,
            data_length=16,
            objects=[
                IODataObject(slot=1, subslot=1, frame_offset=0, data_length=4, iops_offset=4),
            ],
        )
        builder = CyclicDataBuilder(config)

        # Set data and swap to initialize send buffer
        builder.set_data(1, 1, b"\x01\x02\x03\x04")
        builder.swap()

        # Now write new data without swapping
        builder.set_data(1, 1, b"\xaa\xbb\xcc\xdd")

        # build() should still return old data from send buffer
        payload = builder.build()
        assert payload[0:4] == b"\x01\x02\x03\x04"

        # After swap, build() returns new data
        builder.swap()
        payload = builder.build()
        assert payload[0:4] == b"\xaa\xbb\xcc\xdd"

    def test_swap_skips_when_not_dirty(self):
        """Swap is a no-op when write buffer hasn't changed."""
        config = IOCRConfig(
            iocr_type=IOCR_TYPE_OUTPUT,
            iocr_reference=1,
            frame_id=0xC000,
            data_length=16,
            objects=[
                IODataObject(slot=1, subslot=1, frame_offset=0, data_length=4, iops_offset=4),
            ],
        )
        builder = CyclicDataBuilder(config)
        builder.set_data(1, 1, b"\x01\x02\x03\x04")
        builder.swap()

        # Dirty flag should be cleared
        assert not builder._dirty

        # Swap again should be no-op
        builder.swap()
        assert not builder._dirty

    def test_concurrent_set_and_build(self):
        """Concurrent writes and builds don't corrupt data."""
        import threading

        config = IOCRConfig(
            iocr_type=IOCR_TYPE_OUTPUT,
            iocr_reference=1,
            frame_id=0xC000,
            data_length=16,
            objects=[
                IODataObject(slot=1, subslot=1, frame_offset=0, data_length=4, iops_offset=4),
            ],
        )
        builder = CyclicDataBuilder(config)

        errors = []
        iterations = 1000

        def writer():
            for i in range(iterations):
                val = (i & 0xFF).to_bytes(1, "big") * 4
                builder.set_data(1, 1, val)

        def reader():
            for _ in range(iterations):
                builder.swap()
                payload = builder.build()
                # All 4 bytes should be the same value (no partial writes)
                if payload[0:4] != bytes([payload[0]]) * 4:
                    errors.append(f"Inconsistent: {payload[0:4].hex()}")

        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=reader)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(errors) == 0, f"Data corruption detected: {errors[:5]}"


class TestEthernetFrameHelpers:
    """Test Ethernet frame building and parsing helpers."""

    def test_build_ethernet_frame(self):
        """Test building complete Ethernet frame."""
        dst = b"\xd0\xc8\x57\xe0\x1c\x2c"
        src = b"\x00\x11\x22\x33\x44\x55"
        rt = RTFrame(0xC000, 100, 0xA4, 0, b"\x01\x02\x03\x04")

        eth = build_ethernet_frame(dst, src, rt)

        assert eth[0:6] == dst
        assert eth[6:12] == src
        assert eth[12:14] == b"\x88\x92"  # PROFINET EtherType
        assert eth[14:16] == b"\xc0\x00"  # Frame ID

    def test_parse_ethernet_frame(self):
        """Test parsing Ethernet frame."""
        # Build a valid frame
        dst = b"\xd0\xc8\x57\xe0\x1c\x2c"
        src = b"\x00\x11\x22\x33\x44\x55"
        rt_data = b"\xc0\x00\x01\x02\x03\x04\x00\x64\xa4\x00"  # RT frame
        eth = dst + src + b"\x88\x92" + rt_data

        frame = parse_ethernet_frame(eth)

        assert frame is not None
        assert frame.frame_id == 0xC000
        assert frame.cycle_counter == 100
        assert frame.payload == b"\x01\x02\x03\x04"

    def test_parse_non_profinet_returns_none(self):
        """Test parsing non-PROFINET frame returns None."""
        # IPv4 frame
        dst = b"\xd0\xc8\x57\xe0\x1c\x2c"
        src = b"\x00\x11\x22\x33\x44\x55"
        eth = dst + src + b"\x08\x00" + b"\x00" * 20  # IPv4

        frame = parse_ethernet_frame(eth)
        assert frame is None

    def test_parse_too_short_returns_none(self):
        """Test parsing too-short frame returns None."""
        frame = parse_ethernet_frame(b"\x00" * 10)
        assert frame is None
