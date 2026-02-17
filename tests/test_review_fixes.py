"""Tests for code review fixes (H-1 through M-10).

Verifies the fixes for issues found during code review of the
non-cyclic PROFINET code.
"""

import struct
import time
from unittest.mock import MagicMock, patch

from profinet.dcp import (
    DCP_HELLO_MULTICAST_MAC,
    DCP_MULTICAST_MAC,
    DCPDeviceDescription,
    read_response,
)
from profinet.protocol import (
    PNDCPBlock,
    PNRPCHeader,
    PNRTAHeader,
)

# =============================================================================
# H-1: DREP-aware RPC response parsing
# =============================================================================


class TestDREPAwareParsing:
    """Test that _send_receive correctly handles DREP byte order."""

    def _build_rpc_response(self, drep_byte=0x00, operation=0x02, body_len=20):
        """Build a minimal RPC response packet.

        Args:
            drep_byte: 0x00 for big-endian, 0x10 for little-endian
            operation: operation number
            body_len: length_of_body value
        """
        bo = "<" if (drep_byte & 0x10) else ">"

        # Header: single-byte fields (endian-independent)
        hdr = struct.pack(
            "BBBB3sB",
            0x04,  # version
            PNRPCHeader.RESPONSE,  # packet_type
            0x00,  # flags1
            0x00,  # flags2
            bytes([drep_byte, 0x00, 0x00]),  # drep
            0x00,  # serial_high
        )
        # UUIDs (16 bytes each)
        hdr += b"\x00" * 16  # object_uuid
        hdr += b"\x00" * 16  # interface_uuid
        hdr += b"\x00" * 16  # activity_uuid
        # Multi-byte fields in DREP byte order
        hdr += struct.pack(
            f"{bo}IIIHHHHHBB",
            0,  # server_boot_time
            1,  # interface_version
            42,  # sequence_number
            operation,  # operation_number
            0xFFFF,  # interface_hint
            0xFFFF,  # activity_hint
            body_len,  # length_of_body
            0,  # fragment_number
            0,  # auth_protocol
            0,  # serial_low
        )
        # Payload
        hdr += b"\x00" * body_len
        return hdr

    def test_parse_rpc_header_big_endian(self):
        """Test _parse_rpc_header correctly parses big-endian response."""
        from profinet.rpc import RPCCon

        data = self._build_rpc_response(drep_byte=0x00, operation=0x02, body_len=20)
        result = RPCCon._parse_rpc_header(data)

        assert result is not None
        assert result["is_little_endian"] is False
        assert result["operation_number"] == 0x02
        assert result["length_of_body"] == 20
        assert result["sequence_number"] == 42

    def test_parse_rpc_header_little_endian(self):
        """Test _parse_rpc_header correctly parses little-endian response."""
        from profinet.rpc import RPCCon

        data = self._build_rpc_response(drep_byte=0x10, operation=0x02, body_len=20)
        result = RPCCon._parse_rpc_header(data)

        assert result is not None
        assert result["is_little_endian"] is True
        assert result["operation_number"] == 0x02
        assert result["length_of_body"] == 20
        assert result["sequence_number"] == 42

    def test_big_endian_vs_little_endian_differ_without_drep(self):
        """Show that without DREP awareness, LE fields are misinterpreted.

        A big-endian parser would read operation=0x0200 for a LE packet
        with operation=0x02. This confirms the bug existed.
        """
        # Build LE packet
        data = self._build_rpc_response(drep_byte=0x10, operation=0x02, body_len=20)

        # Parse with big-endian (wrong)
        wrong_op = struct.unpack_from(">H", data, 68)[0]
        # Parse with little-endian (correct, via DREP)
        correct_op = struct.unpack_from("<H", data, 68)[0]

        assert correct_op == 0x02
        # Big-endian misreads it (0x0200 for value 2 in LE)
        assert wrong_op == 0x0200

    def test_parse_rpc_header_too_short(self):
        """Test _parse_rpc_header returns None for short data."""
        from profinet.rpc import RPCCon

        assert RPCCon._parse_rpc_header(b"\x00" * 10) is None
        assert RPCCon._parse_rpc_header(b"") is None


# =============================================================================
# H-2: Timeout uses monotonic clock and total_seconds
# =============================================================================


class TestCheckTimeout:
    """Test _check_timeout uses monotonic clock."""

    def test_check_timeout_uses_monotonic(self):
        """Verify _check_timeout uses _live_monotonic (monotonic clock)."""
        from profinet.rpc import RPCCon

        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 1] + [255, 255, 255, 0] + [0, 0, 0, 0]),
            PNDCPBlock.DEVICE_ID: bytes([0, 0, 0, 1]),
        }
        info = DCPDeviceDescription(b"\x00" * 6, blocks)

        with patch("profinet.rpc.socket"):
            rpc = RPCCon(info)

            # Set _live_monotonic to a recent time -- should NOT trigger reconnect
            rpc._live_monotonic = time.monotonic()
            rpc.live = True  # non-None so _check_timeout proceeds
            rpc.connect = MagicMock()

            rpc._check_timeout()
            rpc.connect.assert_not_called()

            # Set _live_monotonic far in the past -- should trigger reconnect
            rpc._live_monotonic = time.monotonic() - 100
            rpc._check_timeout()
            rpc.connect.assert_called_once()

            rpc.close()


# =============================================================================
# H-3: DCP Hello multicast address
# =============================================================================


class TestDCPHelloMulticast:
    """Test DCP Hello uses correct multicast address."""

    def test_hello_multicast_constant_defined(self):
        """Verify DCP_HELLO_MULTICAST_MAC exists and is correct."""
        assert DCP_HELLO_MULTICAST_MAC == "01:0e:cf:00:00:01"

    def test_identify_multicast_unchanged(self):
        """Verify DCP_MULTICAST_MAC for Identify is unchanged."""
        assert DCP_MULTICAST_MAC == "01:0e:cf:00:00:00"

    def test_hello_and_identify_differ(self):
        """Verify Hello and Identify use different addresses."""
        assert DCP_HELLO_MULTICAST_MAC != DCP_MULTICAST_MAC


# =============================================================================
# H-4: AlarmAck RTA PDU type
# =============================================================================


class TestAlarmAckPDUType:
    """Test AlarmAck uses RTA_TYPE_DATA, not RTA_TYPE_ACK."""

    def test_rta_type_data_for_alarm_ack(self):
        """Verify AlarmAck uses RTA_TYPE_DATA (0x01) not RTA_TYPE_ACK (0x03)."""
        from profinet.alarm_listener import AlarmEndpoint, AlarmListener

        endpoint = AlarmEndpoint(
            interface="lo",
            controller_ref=1,
            device_ref=42,
            device_mac=b"\x00" * 6,
        )
        listener = AlarmListener(endpoint, controller_mac=b"\x11" * 6)
        listener._sock = MagicMock()

        # Build minimal ack data
        ack_data = b"\x00" * 20

        # Call _send_layer2_ack
        listener._send_layer2_ack(ack_data, b"\x22" * 6, high_priority=False)

        # Verify the frame was sent
        assert listener._sock.send.called
        sent_frame = listener._sock.send.call_args[0][0]

        # Parse the RTA header: starts after dst(6) + src(6) + ethertype(2) + frame_id(2) = 16
        rta_pdu_type = sent_frame[16 + 4]  # offset 4 in RTA header is pdu_type
        rta_type = (rta_pdu_type >> 4) & 0x0F
        rta_version = rta_pdu_type & 0x0F

        assert rta_type == PNRTAHeader.RTA_TYPE_DATA  # 0x01, not 0x03
        assert rta_version == PNRTAHeader.VERSION_1


# =============================================================================
# M-1: Session key randomization
# =============================================================================


class TestSessionKey:
    """Test session key is randomized, not hardcoded."""

    def test_session_key_not_hardcoded(self):
        """Verify session key is not always 0x1234."""
        from profinet.rpc import RPCCon

        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 1] + [255, 255, 255, 0] + [0, 0, 0, 0]),
            PNDCPBlock.DEVICE_ID: bytes([0, 0, 0, 1]),
        }
        info = DCPDeviceDescription(b"\x00" * 6, blocks)

        with patch("profinet.rpc.socket"):
            # Create multiple instances and check they don't all have 0x1234
            keys = set()
            for _ in range(10):
                rpc = RPCCon(info)
                keys.add(rpc.session_key)
                rpc.close()

            # With random keys, we should get more than 1 unique value
            assert len(keys) > 1, f"Session key appears hardcoded: {keys}"

    def test_session_key_is_nonzero(self):
        """Verify session key is never zero (per spec)."""
        from profinet.rpc import RPCCon

        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 1] + [255, 255, 255, 0] + [0, 0, 0, 0]),
            PNDCPBlock.DEVICE_ID: bytes([0, 0, 0, 1]),
        }
        info = DCPDeviceDescription(b"\x00" * 6, blocks)

        with patch("profinet.rpc.socket"):
            for _ in range(100):
                rpc = RPCCon(info)
                assert rpc.session_key != 0, "Session key must not be zero"
                rpc.close()


# =============================================================================
# M-4: UUID regeneration on reconnect
# =============================================================================


class TestUUIDRegeneration:
    """Test UUIDs are regenerated on reconnect."""

    def test_uuids_regenerated_on_reconnect(self):
        """Verify ar_uuid and activity_uuid change on reconnect."""
        from profinet.rpc import RPCCon

        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 1] + [255, 255, 255, 0] + [0, 0, 0, 0]),
            PNDCPBlock.DEVICE_ID: bytes([0, 0, 0, 1]),
        }
        info = DCPDeviceDescription(b"\x00" * 6, blocks)

        with patch("profinet.rpc.socket"):
            rpc = RPCCon(info)

            original_ar_uuid = rpc.ar_uuid
            original_activity_uuid = rpc.activity_uuid

            # Simulate a previous connection
            rpc.live = True
            rpc.src_mac = b"\x00" * 6

            # Mock _send_receive to avoid actual network I/O
            rpc._send_receive = MagicMock(side_effect=Exception("test"))

            try:
                rpc.connect()
            except Exception:
                pass

            # UUIDs should be different after reconnect
            assert rpc.ar_uuid != original_ar_uuid
            assert rpc.activity_uuid != original_activity_uuid

            rpc.close()


# =============================================================================
# M-5: DCP response XID validation
# =============================================================================


class TestXIDValidation:
    """Test read_response XID validation parameter."""

    def test_read_response_accepts_expected_xid_param(self):
        """Verify read_response accepts expected_xid parameter."""
        import inspect

        sig = inspect.signature(read_response)
        assert "expected_xid" in sig.parameters


# =============================================================================
# M-9: Alarm ACK frame ID matches priority
# =============================================================================


class TestAlarmAckFrameID:
    """Test alarm ACK frame ID matches alarm priority."""

    def test_high_priority_alarm_uses_high_frame_id(self):
        """Verify high-priority alarm ack uses FRAME_ID_ALARM_HIGH."""
        from profinet.alarm_listener import (
            FRAME_ID_ALARM_HIGH,
            AlarmEndpoint,
            AlarmListener,
        )

        endpoint = AlarmEndpoint(
            interface="lo",
            controller_ref=1,
            device_ref=42,
            device_mac=b"\x00" * 6,
        )
        listener = AlarmListener(endpoint, controller_mac=b"\x11" * 6)
        listener._sock = MagicMock()

        ack_data = b"\x00" * 20
        listener._send_layer2_ack(ack_data, b"\x22" * 6, high_priority=True)

        sent_frame = listener._sock.send.call_args[0][0]
        # Frame ID is at offset 14 (after dst+src+ethertype)
        frame_id = struct.unpack_from(">H", sent_frame, 14)[0]
        assert frame_id == FRAME_ID_ALARM_HIGH

    def test_low_priority_alarm_uses_low_frame_id(self):
        """Verify low-priority alarm ack uses FRAME_ID_ALARM_LOW."""
        from profinet.alarm_listener import (
            FRAME_ID_ALARM_LOW,
            AlarmEndpoint,
            AlarmListener,
        )

        endpoint = AlarmEndpoint(
            interface="lo",
            controller_ref=1,
            device_ref=42,
            device_mac=b"\x00" * 6,
        )
        listener = AlarmListener(endpoint, controller_mac=b"\x11" * 6)
        listener._sock = MagicMock()

        ack_data = b"\x00" * 20
        listener._send_layer2_ack(ack_data, b"\x22" * 6, high_priority=False)

        sent_frame = listener._sock.send.call_args[0][0]
        frame_id = struct.unpack_from(">H", sent_frame, 14)[0]
        assert frame_id == FRAME_ID_ALARM_LOW
