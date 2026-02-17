"""Tests for profinet.util module."""

import pytest

from profinet.exceptions import InvalidIPError, InvalidMACError
from profinet.util import (
    decode_bytes,
    ip2s,
    mac2s,
    s2ip,
    s2mac,
    to_hex,
)


class TestMACConversion:
    """Test MAC address conversion functions."""

    def test_s2mac_valid(self):
        """Test valid MAC address string to bytes."""
        result = s2mac("01:02:03:04:05:06")
        assert result == b"\x01\x02\x03\x04\x05\x06"

    def test_s2mac_uppercase(self):
        """Test uppercase MAC address."""
        result = s2mac("AA:BB:CC:DD:EE:FF")
        assert result == b"\xaa\xbb\xcc\xdd\xee\xff"

    def test_s2mac_mixed_case(self):
        """Test mixed case MAC address."""
        result = s2mac("aA:Bb:cC:Dd:Ee:Ff")
        assert result == b"\xaa\xbb\xcc\xdd\xee\xff"

    def test_s2mac_invalid_format(self):
        """Test invalid MAC format raises exception."""
        with pytest.raises(InvalidMACError):
            s2mac("invalid-mac")

    def test_s2mac_empty(self):
        """Test empty MAC raises exception."""
        with pytest.raises(InvalidMACError):
            s2mac("")

    def test_s2mac_too_short(self):
        """Test too short MAC raises exception."""
        with pytest.raises(InvalidMACError):
            s2mac("01:02:03")

    def test_mac2s_valid(self):
        """Test valid bytes to MAC string."""
        result = mac2s(b"\x01\x02\x03\x04\x05\x06")
        assert result == "01:02:03:04:05:06"

    def test_mac2s_invalid_length(self):
        """Test invalid length raises exception."""
        with pytest.raises(InvalidMACError):
            mac2s(b"\x01\x02\x03")

    def test_mac_roundtrip(self):
        """Test MAC conversion roundtrip."""
        original = "de:ad:be:ef:ca:fe"
        assert mac2s(s2mac(original)) == original


class TestIPConversion:
    """Test IP address conversion functions."""

    def test_s2ip_valid(self):
        """Test valid bytes to IP string."""
        result = s2ip(b"\xc0\xa8\x01\x01")
        assert result == "192.168.1.1"

    def test_s2ip_zeros(self):
        """Test zero IP address."""
        result = s2ip(b"\x00\x00\x00\x00")
        assert result == "0.0.0.0"

    def test_s2ip_broadcast(self):
        """Test broadcast IP address."""
        result = s2ip(b"\xff\xff\xff\xff")
        assert result == "255.255.255.255"

    def test_s2ip_too_short(self):
        """Test too short bytes raises exception."""
        with pytest.raises(InvalidIPError):
            s2ip(b"\x01\x02")

    def test_ip2s_valid(self):
        """Test valid IP string to bytes."""
        result = ip2s("192.168.1.1")
        assert result == b"\xc0\xa8\x01\x01"

    def test_ip2s_zeros(self):
        """Test zero IP address."""
        result = ip2s("0.0.0.0")
        assert result == b"\x00\x00\x00\x00"

    def test_ip2s_invalid_format(self):
        """Test invalid IP format raises exception."""
        with pytest.raises(InvalidIPError):
            ip2s("invalid.ip")

    def test_ip2s_out_of_range(self):
        """Test out of range octet raises exception."""
        with pytest.raises(InvalidIPError):
            ip2s("256.1.1.1")

    def test_ip2s_empty(self):
        """Test empty IP raises exception."""
        with pytest.raises(InvalidIPError):
            ip2s("")

    def test_ip_roundtrip(self):
        """Test IP conversion roundtrip."""
        original = "10.20.30.40"
        assert s2ip(ip2s(original)) == original


class TestHelperFunctions:
    """Test helper utility functions."""

    def test_to_hex(self):
        """Test bytes to hex string."""
        result = to_hex(b"\x01\x02\x03")
        assert result == "01:02:03"

    def test_to_hex_empty(self):
        """Test empty bytes."""
        result = to_hex(b"")
        assert result == ""

    def test_decode_bytes(self):
        """Test bytes decoding with null stripping."""
        result = decode_bytes(b"hello\x00\x00")
        assert result == "hello"

    def test_decode_bytes_no_null(self):
        """Test bytes decoding without null."""
        result = decode_bytes(b"hello")
        assert result == "hello"

    def test_decode_bytes_all_nulls(self):
        """Test bytes decoding with all null bytes."""
        result = decode_bytes(b"\x00\x00\x00")
        assert result == ""

    def test_decode_bytes_empty(self):
        """Test bytes decoding with empty input."""
        result = decode_bytes(b"")
        assert result == ""

    def test_decode_bytes_non_utf8(self):
        """Test bytes decoding with non-UTF-8 data uses replace."""
        # 0xFF is not valid UTF-8; should use replacement character
        result = decode_bytes(b"\xff\xfe")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_decode_bytes_null_padded_string(self):
        """Test bytes decoding with null-padded fixed-length field."""
        # Simulate a 20-byte order_id field
        result = decode_bytes(b"6ES7 214-1AG40\x00\x00\x00\x00\x00\x00")
        assert result == "6ES7 214-1AG40"


# =============================================================================
# MaxTimeout Tests
# =============================================================================


import struct
import time

from profinet.util import MaxTimeout, max_timeout


class TestMaxTimeout:
    """Test MaxTimeout context manager."""

    def test_basic_usage(self):
        """Test basic MaxTimeout usage."""
        with MaxTimeout(1.0) as t:
            assert t.timed_out is False

    def test_timeout_expires(self):
        """Test MaxTimeout times out after specified seconds."""
        with MaxTimeout(0.1) as t:
            time.sleep(0.2)
            assert t.timed_out is True

    def test_remaining_decreases(self):
        """Test remaining time decreases over time."""
        with MaxTimeout(2.0) as t:
            remaining1 = t.remaining
            time.sleep(0.1)
            remaining2 = t.remaining
            assert remaining2 < remaining1

    def test_remaining_non_negative(self):
        """Test remaining returns 0 when expired, not negative."""
        with MaxTimeout(0.01) as t:
            time.sleep(0.05)
            assert t.remaining == 0

    def test_backwards_compat_alias(self):
        """Test max_timeout is an alias for MaxTimeout."""
        assert max_timeout is MaxTimeout

    def test_seconds_attribute(self):
        """Test seconds attribute stores the configured timeout."""
        with MaxTimeout(5.0) as t:
            assert t.seconds == 5.0

    def test_exit_does_not_suppress_exceptions(self):
        """Test __exit__ does not suppress exceptions."""
        with pytest.raises(ValueError):
            with MaxTimeout(10.0):
                raise ValueError("test error")


# =============================================================================
# make_packet VLF Tests
# =============================================================================

from profinet.protocol import PNBlockHeader, PNDCPBlock, PNDCPBlockRequest


class TestMakePacketVLF:
    """Test make_packet with variable-length field (VLF)."""

    def test_vlf_parsing(self):
        """Test parsing a packet with variable-length field."""
        # PNARBlockRequest has VLF for station name
        from profinet.protocol import PNARBlockRequest

        # Build minimal data
        data = bytearray(50)
        # block_header (6 bytes)
        # ar_type (2 bytes) at offset 6
        # ar_uuid (16 bytes) at offset 8
        # session_key (2 bytes) at offset 24
        # cm_initiator_mac_address (6 bytes) at offset 26
        # cm_initiator_object_uuid (16 bytes) at offset 32
        # ar_properties (4 bytes) at offset 48
        # cm_initiator_activity_timeout_factor (2 bytes) at offset 52
        # initiator_udp_rtport (2 bytes) at offset 54
        # station_name_length (2 bytes) at offset 56
        data = bytearray(58)
        struct.pack_into(">H", data, 56, 8)  # station_name_length = 8

        station_name = b"test-dev"
        full_data = bytes(data) + station_name

        pkt = PNARBlockRequest(full_data)
        assert pkt.station_name_length == 8
        assert pkt.cm_initiator_station_name == b"test-dev"

    def test_vlf_serialization(self):
        """Test serialization of packet with VLF includes VLF data."""
        from profinet.protocol import PNARBlockRequest

        data = bytearray(58)
        struct.pack_into(">H", data, 56, 4)
        station_name = b"abcd"
        full_data = bytes(data) + station_name

        pkt = PNARBlockRequest(full_data)
        serialized = bytes(pkt)

        # The serialized data should end with the station name
        assert serialized[-4:] == b"abcd"


class TestMakePacketPayloadSizeField:
    """Test make_packet with payload_size_field."""

    def test_payload_size_field_parsing(self):
        """Test PNDCPBlockRequest uses length field for payload size."""
        # option(1) + suboption(1) + length(2) + payload
        data = b"\x02\x02\x00\x05" + b"hello"
        pkt = PNDCPBlockRequest(data)
        assert pkt.option == 0x02
        assert pkt.suboption == 0x02
        assert pkt.length == 5
        assert pkt.payload == b"hello"

    def test_payload_offset_parsing(self):
        """Test PNDCPBlock uses payload_offset for status bytes."""
        # option(1) + suboption(1) + length(2) + status(2) + payload
        # length = 7 (includes status), payload = length - 2 = 5
        data = b"\x02\x02\x00\x07\x00\x00" + b"world"
        pkt = PNDCPBlock(data)
        assert pkt.length == 7
        assert pkt.status == 0x0000
        assert pkt.payload == b"world"


class TestMakePacketNoPayload:
    """Test make_packet with payload=False."""

    def test_no_payload_packet(self):
        """Test PNBlockHeader has no payload attribute."""
        data = struct.pack(">HHBB", 0x0020, 0x003C, 0x01, 0x00)
        pkt = PNBlockHeader(data)
        assert not hasattr(pkt, "payload")

    def test_no_payload_len(self):
        """Test len() on no-payload packet returns header size only."""
        pkt = PNBlockHeader(0x0020, 0x003C, 0x01, 0x00)
        assert len(pkt) == 6  # HHBB = 2+2+1+1
