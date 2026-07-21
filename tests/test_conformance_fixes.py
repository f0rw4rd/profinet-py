"""Regression tests for conformance fixes found by cross-checking against
the p-net certified device stack and the Wireshark PROFINET dissectors.

Covers:
- VLAN tag handling on RX (cyclic + alarms)
- RTA transport-acknowledge handshake (TACK, sequence numbers, PDU dispatch)
- Cyclic TX behavior in FAULT and TransferStatus validation
- DCP Set wire format (odd-length padding, BlockQualifier, Signal)
- NDR ArgsMaximum sizing
- Output IOCR frame ID convention (0xFFFF, device assigns)
"""

import struct
from unittest.mock import MagicMock

import pytest

from profinet.alarm_listener import (
    ADD_FLAGS_TACK,
    ADD_FLAGS_WINDOW_1,
    AlarmEndpoint,
    AlarmListener,
)
from profinet.alarms import parse_alarm_notification
from profinet.cyclic import CyclicController, CyclicState
from profinet.dcp import set_param, signal_device
from profinet.exceptions import DCPError
from profinet.protocol import PNRTAHeader
from profinet.rpc import NDR_ARGS_MAXIMUM, RPCCon
from profinet.rt import (
    IOCR_TYPE_INPUT,
    IOCR_TYPE_OUTPUT,
    IOCRConfig,
    IODataObject,
    RTFrame,
)
from profinet.util import skip_vlan_tags

CTRL_MAC = b"\x00\x11\x22\x33\x44\x55"
DEV_MAC = b"\xd0\xc8\x57\xe0\x1c\x2c"
VLAN_TAG = b"\x81\x00\xc0\x00"  # TPID 0x8100, PCP 6, VID 0


# =============================================================================
# util.skip_vlan_tags
# =============================================================================


class TestSkipVlanTags:
    def test_untagged(self):
        frame = DEV_MAC + CTRL_MAC + b"\x88\x92" + b"\x00" * 50
        assert skip_vlan_tags(frame) == 12

    def test_single_8021q_tag(self):
        frame = DEV_MAC + CTRL_MAC + VLAN_TAG + b"\x88\x92" + b"\x00" * 50
        assert skip_vlan_tags(frame) == 16

    def test_double_tag_qinq(self):
        frame = DEV_MAC + CTRL_MAC + b"\x88\xa8\x00\x00" + VLAN_TAG + b"\x88\x92" + b"\x00" * 50
        assert skip_vlan_tags(frame) == 20

    def test_short_frame(self):
        assert skip_vlan_tags(b"\x00" * 13) == 12


# =============================================================================
# Cyclic RX: VLAN tags, TransferStatus, FAULT TX
# =============================================================================


def make_input_iocr():
    return IOCRConfig(
        iocr_type=IOCR_TYPE_INPUT,
        iocr_reference=1,
        frame_id=0xC001,
        send_clock_factor=1,
        reduction_ratio=1,
        watchdog_factor=3,
        data_length=40,
        objects=[IODataObject(slot=1, subslot=1, frame_offset=0, data_length=4, iops_offset=4)],
    )


def make_output_iocr():
    return IOCRConfig(
        iocr_type=IOCR_TYPE_OUTPUT,
        iocr_reference=2,
        frame_id=0xC000,
        send_clock_factor=32,
        reduction_ratio=32,
        watchdog_factor=3,
        data_length=40,
        objects=[IODataObject(slot=1, subslot=1, frame_offset=0, data_length=4, iops_offset=4)],
    )


def make_controller():
    return CyclicController(
        interface="eth0",
        src_mac=CTRL_MAC,
        dst_mac=DEV_MAC,
        input_iocr=make_input_iocr(),
        output_iocr=make_output_iocr(),
    )


def build_input_eth_frame(vlan=False, transfer_status=0, payload=None):
    """Device -> controller cyclic frame for the input IOCR (0xC001)."""
    if payload is None:
        payload = b"\xaa\xbb\xcc\xdd" + b"\x80" + b"\x00" * 35  # data + IOPS GOOD + pad
    rt = RTFrame(
        frame_id=0xC001,
        cycle_counter=1,
        data_status=RTFrame.DATA_VALID | RTFrame.DATA_RUN,
        transfer_status=transfer_status,
        payload=payload,
    )
    tag = VLAN_TAG if vlan else b""
    return CTRL_MAC + DEV_MAC + tag + b"\x88\x92" + rt.to_bytes()


class TestCyclicRxConformance:
    def test_untagged_input_frame_accepted(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        ctrl._process_input_frame(build_input_eth_frame(vlan=False))
        assert ctrl.stats.frames_received == 1
        assert ctrl.get_input_data(1, 1) == b"\xaa\xbb\xcc\xdd"

    def test_vlan_tagged_input_frame_accepted(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        ctrl._process_input_frame(build_input_eth_frame(vlan=True))
        assert ctrl.stats.frames_received == 1
        assert ctrl.get_input_data(1, 1) == b"\xaa\xbb\xcc\xdd"

    def test_nonzero_transfer_status_dropped(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        ctrl._process_input_frame(build_input_eth_frame(transfer_status=1))
        assert ctrl.stats.frames_invalid == 1
        assert ctrl.get_input_data(1, 1) is None

    def test_tx_continues_in_fault(self):
        """A controller that stops sending makes the device's DHT expire
        and abort the AR, so FAULT must not stop the TX path."""
        ctrl = make_controller()
        ctrl._state = CyclicState.FAULT
        ctrl._send_output_frame = MagicMock()
        ctrl._tx_cycle()
        ctrl._send_output_frame.assert_called_once()
        assert ctrl.stats.frames_sent == 1

    def test_rx_socket_binds_all_protocols(self, monkeypatch):
        """RX must bind ETH_P_ALL: a 0x8892-bound socket never sees
        VLAN-tagged frames unless the NIC strips the tag."""
        import profinet.cyclic as cyclic_mod

        captured = {}

        def fake_socket(interface, ethertype):
            captured["ethertype"] = ethertype
            return MagicMock()

        monkeypatch.setattr(cyclic_mod, "_ethernet_socket", fake_socket)
        ctrl = make_controller()
        ctrl._create_raw_socket(timeout=0.001, ethertype=None)
        assert captured["ethertype"] is None


# =============================================================================
# Alarm listener: RTA transport-acknowledge handshake
# =============================================================================


def build_alarm_block(high_priority=False, specifier=0x0400 | 1):
    """Minimal valid AlarmNotification block (diagnosis alarm, slot 1)."""
    body = struct.pack(">HIHHIIH", 0x0001, 0, 1, 1, 0x01, 0x01, specifier)
    block_type = 0x0001 if high_priority else 0x0002
    return struct.pack(">HHBB", block_type, len(body) + 2, 1, 0) + body + b"\x00\x00"


def build_rta_frame(
    pdu_type,
    add_flags,
    send_seq,
    ack_seq,
    var_part=b"",
    dst_ref=1,
    src_ref=42,
    version=1,
    vlan=False,
    frame_id=0xFE01,
):
    """Device -> controller RTA PDU as a raw Ethernet frame."""
    rta = struct.pack(
        ">HHBBHHH",
        dst_ref,
        src_ref,
        (version << 4) | pdu_type,
        add_flags,
        send_seq,
        ack_seq,
        len(var_part),
    )
    tag = VLAN_TAG if vlan else b""
    return CTRL_MAC + DEV_MAC + tag + b"\x88\x92" + struct.pack(">H", frame_id) + rta + var_part


def parse_sent_rta(frame):
    """Parse a frame our listener sent: returns (frame_id, rta fields, var_part)."""
    assert frame[0:6] == DEV_MAC
    assert frame[6:12] == CTRL_MAC
    assert frame[12:14] == b"\x88\x92"
    frame_id = struct.unpack(">H", frame[14:16])[0]
    dst_ref, src_ref, pdu_type, add_flags, send_seq, ack_seq, var_len = struct.unpack(
        ">HHBBHHH", frame[16:28]
    )
    var_part = frame[28:]
    assert var_len == len(var_part)
    return {
        "frame_id": frame_id,
        "dst_ref": dst_ref,
        "src_ref": src_ref,
        "pdu_type": pdu_type,
        "add_flags": add_flags,
        "send_seq": send_seq,
        "ack_seq": ack_seq,
        "var_part": var_part,
    }


def make_listener():
    endpoint = AlarmEndpoint(interface="eth0", controller_ref=1, device_ref=42, device_mac=DEV_MAC)
    listener = AlarmListener(endpoint, controller_mac=CTRL_MAC)
    listener._sock = MagicMock()
    return listener


def feed(listener, frame):
    listener._sock.recv.return_value = frame
    listener._handle_layer2_frame()


def sent_frames(listener):
    return [parse_sent_rta(c.args[0]) for c in listener._sock.send.call_args_list]


class TestRTAHandshake:
    def test_notification_gets_transport_ack_then_alarm_ack(self):
        listener = make_listener()
        alarms = []
        listener.add_callback(alarms.append)

        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_DATA,
                ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
                send_seq=0xFFFF,
                ack_seq=0xFFFE,
                var_part=build_alarm_block(),
            ),
        )

        sent = sent_frames(listener)
        assert len(sent) == 2

        # 1st frame: pure transport ACK (TACK) with empty var part
        tack = sent[0]
        assert tack["pdu_type"] == 0x13  # version 1 high nibble, ACK low nibble
        assert tack["add_flags"] == ADD_FLAGS_WINDOW_1  # window size 1, no TACK bit
        assert tack["send_seq"] == 0xFFFE
        assert tack["ack_seq"] == 0xFFFF  # echoes the device's SendSeqNum
        assert tack["var_part"] == b""
        assert tack["dst_ref"] == 42 and tack["src_ref"] == 1

        # 2nd frame: application AlarmAck as DATA with TACK requested
        ack = sent[1]
        assert ack["pdu_type"] == 0x11
        assert ack["add_flags"] == ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK
        assert ack["send_seq"] == 0xFFFF  # first DATA uses initial counter
        assert ack["ack_seq"] == 0xFFFF
        assert struct.unpack(">H", ack["var_part"][0:2])[0] == 0x8002  # AlarmAck Low

        # Receive counters advanced (0xFFFF accepted, next expected is 0)
        assert listener._exp_seq_num == 0x0000
        assert listener._exp_seq_num_o == 0xFFFF
        assert len(alarms) == 1

    def test_duplicate_notification_is_reacked_not_reprocessed(self):
        listener = make_listener()
        alarms = []
        listener.add_callback(alarms.append)
        frame = build_rta_frame(
            PNRTAHeader.RTA_TYPE_DATA,
            ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
            send_seq=0xFFFF,
            ack_seq=0xFFFE,
            var_part=build_alarm_block(),
        )
        feed(listener, frame)
        listener._sock.send.reset_mock()

        feed(listener, frame)  # retransmission of the same PDU

        sent = sent_frames(listener)
        assert len(sent) == 1
        assert sent[0]["pdu_type"] == 0x13  # ACK only, nothing reprocessed
        assert len(alarms) == 1

    def test_out_of_sequence_notification_gets_nack(self):
        listener = make_listener()
        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_DATA,
                ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
                send_seq=5,
                ack_seq=0xFFFE,
                var_part=build_alarm_block(),
            ),
        )
        sent = sent_frames(listener)
        assert len(sent) == 1
        assert sent[0]["pdu_type"] == 0x12  # NACK
        assert listener._exp_seq_num == 0xFFFF  # unchanged

    def test_data_without_tack_is_ignored(self):
        listener = make_listener()
        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_DATA,
                ADD_FLAGS_WINDOW_1,
                send_seq=0xFFFF,
                ack_seq=0xFFFE,
                var_part=build_alarm_block(),
            ),
        )
        listener._sock.send.assert_not_called()

    def test_pure_ack_advances_send_counter(self):
        listener = make_listener()
        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_ACK, ADD_FLAGS_WINDOW_1, send_seq=0xFFFE, ack_seq=0xFFFF
            ),
        )
        assert listener._send_seq_num == 0x0000
        assert listener._send_seq_num_o == 0xFFFF
        listener._sock.send.assert_not_called()

    def test_stale_ack_does_not_advance(self):
        listener = make_listener()
        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_ACK, ADD_FLAGS_WINDOW_1, send_seq=0xFFFE, ack_seq=5
            ),
        )
        assert listener._send_seq_num == 0xFFFF

    def test_err_pdu_logged_not_acked(self):
        listener = make_listener()
        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_ERR,
                ADD_FLAGS_WINDOW_1,
                send_seq=0xFFFE,
                ack_seq=0xFFFE,
                var_part=b"\xcf\x81\xfd\x05",
            ),
        )
        listener._sock.send.assert_not_called()

    def test_wrong_version_ignored(self):
        listener = make_listener()
        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_DATA,
                ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
                send_seq=0xFFFF,
                ack_seq=0xFFFE,
                var_part=build_alarm_block(),
                version=2,
            ),
        )
        listener._sock.send.assert_not_called()

    def test_wrong_dst_ref_ignored(self):
        listener = make_listener()
        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_DATA,
                ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
                send_seq=0xFFFF,
                ack_seq=0xFFFE,
                var_part=build_alarm_block(),
                dst_ref=99,
            ),
        )
        listener._sock.send.assert_not_called()

    def test_vlan_tagged_alarm_frame_processed(self):
        listener = make_listener()
        alarms = []
        listener.add_callback(alarms.append)
        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_DATA,
                ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
                send_seq=0xFFFF,
                ack_seq=0xFFFE,
                var_part=build_alarm_block(),
                vlan=True,
            ),
        )
        assert len(alarms) == 1
        assert len(sent_frames(listener)) == 2

    def test_high_priority_uses_high_frame_id(self):
        listener = make_listener()
        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_DATA,
                ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
                send_seq=0xFFFF,
                ack_seq=0xFFFE,
                var_part=build_alarm_block(high_priority=True),
                frame_id=0xFC01,
            ),
        )
        sent = sent_frames(listener)
        assert len(sent) == 2
        assert all(f["frame_id"] == 0xFC01 for f in sent)
        assert struct.unpack(">H", sent[1]["var_part"][0:2])[0] == 0x8001  # AlarmAck High


class TestRTAIntegration:
    """Full multi-alarm exchange against a simulated device."""

    def test_two_alarm_exchange_with_acks(self):
        listener = make_listener()
        alarms = []
        listener.add_callback(alarms.append)

        # Alarm 1: device DATA seq 0xFFFF
        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_DATA,
                ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
                send_seq=0xFFFF,
                ack_seq=0xFFFE,
                var_part=build_alarm_block(),
            ),
        )
        # Device transport-acks our AlarmAck (seq 0xFFFF)
        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_ACK, ADD_FLAGS_WINDOW_1, send_seq=0xFFFF, ack_seq=0xFFFF
            ),
        )
        assert listener._send_seq_num == 0x0000

        listener._sock.send.reset_mock()

        # Alarm 2: device DATA seq 0x0000
        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_DATA,
                ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
                send_seq=0x0000,
                ack_seq=0x0000,
                var_part=build_alarm_block(),
            ),
        )

        sent = sent_frames(listener)
        assert len(sent) == 2
        assert sent[0]["pdu_type"] == 0x13
        assert sent[0]["ack_seq"] == 0x0000
        assert sent[1]["pdu_type"] == 0x11
        # ack_seq 0x0000 in the DATA piggybacked our pending seq: advanced
        assert sent[1]["send_seq"] == 0x0001
        assert len(alarms) == 2
        assert listener._exp_seq_num == 0x0001

    def test_seq_wrap_at_0x7fff(self):
        listener = make_listener()
        listener._exp_seq_num = 0x7FFF
        listener._exp_seq_num_o = 0x7FFE
        feed(
            listener,
            build_rta_frame(
                PNRTAHeader.RTA_TYPE_DATA,
                ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
                send_seq=0x7FFF,
                ack_seq=0xFFFE,
                var_part=build_alarm_block(),
            ),
        )
        assert listener._exp_seq_num == 0x0000  # wraps modulo 0x8000


class TestAlarmSpecifierBits:
    def test_ar_diagnosis_is_bit15(self):
        alarm = parse_alarm_notification(build_alarm_block(specifier=0x8000 | 1))
        assert alarm.ar_diagnosis_state is True

    def test_reserved_bit14_not_ar_diagnosis(self):
        alarm = parse_alarm_notification(build_alarm_block(specifier=0x4000 | 1))
        assert alarm.ar_diagnosis_state is False


# =============================================================================
# DCP wire format
# =============================================================================

DCP_PAYLOAD_OFFSET = 26  # eth(14) + frame_id(2) + svc(2) + xid(4) + delay(2) + len(2)


def captured_dcp(mock_sock):
    frame = mock_sock.send.call_args.args[0]
    dcp_length = struct.unpack(">H", frame[24:26])[0]
    return frame, dcp_length, frame[DCP_PAYLOAD_OFFSET:]


class TestDCPSetWireFormat:
    def _set_name(self, name, permanent=False):
        sock = MagicMock()
        sock.recv.side_effect = TimeoutError()
        set_param(
            sock,
            CTRL_MAC,
            "AA:BB:CC:DD:EE:FF",
            "name",
            name,
            timeout_sec=1,
            permanent=permanent,
        )
        return captured_dcp(sock)

    def test_odd_length_name_padded_and_counted(self):
        frame, dcp_length, payload = self._set_name("abc")
        # block header(4) + qualifier(2) + name(3) + pad(1)
        assert dcp_length == 10
        assert len(payload) == dcp_length  # pad byte actually on the wire
        assert payload[-1] == 0x00
        block_length = struct.unpack(">H", payload[2:4])[0]
        assert block_length == 5  # qualifier + name, without padding

    def test_even_length_name_not_padded(self):
        frame, dcp_length, payload = self._set_name("abcd")
        assert dcp_length == 10
        assert len(payload) == dcp_length

    def test_temporary_qualifier_default(self):
        _, _, payload = self._set_name("abcd")
        assert payload[4:6] == b"\x00\x00"

    def test_permanent_qualifier(self):
        _, _, payload = self._set_name("abcd", permanent=True)
        assert payload[4:6] == b"\x00\x01"

    def test_set_param_ip_rejected(self):
        sock = MagicMock()
        with pytest.raises(DCPError, match="set_ip"):
            set_param(sock, CTRL_MAC, "AA:BB:CC:DD:EE:FF", "ip", "192.168.0.1")
        sock.send.assert_not_called()


class TestDCPSignalWireFormat:
    def test_signal_is_flash_once(self):
        sock = MagicMock()
        sock.recv.side_effect = TimeoutError()
        signal_device(sock, CTRL_MAC, "AA:BB:CC:DD:EE:FF", timeout_sec=1)
        _, dcp_length, payload = captured_dcp(sock)
        assert dcp_length == 8  # block header(4) + qualifier(2) + signal value(2)
        # BlockQualifier 0x0000, SignalValue 0x0100 ("flash once")
        assert payload[4:8] == b"\x00\x00\x01\x00"


# =============================================================================
# RPC: NDR ArgsMaximum and output IOCR frame ID
# =============================================================================


class TestNdrArgsMaximum:
    def _nrd(self, payload):
        return RPCCon._create_nrd(object.__new__(RPCCon), payload)

    def test_floor_covers_read_responses(self):
        nrd = self._nrd(b"x" * 100)
        assert nrd.args_maximum_status == NDR_ARGS_MAXIMUM
        assert nrd.maximum_count == NDR_ARGS_MAXIMUM

    def test_grows_with_large_requests(self):
        payload = b"x" * 6000
        nrd = self._nrd(payload)
        assert nrd.args_maximum_status >= len(payload)
        assert nrd.maximum_count >= nrd.args_length


class TestOutputIocrFrameId:
    def test_output_frame_id_is_device_assigned(self):
        from profinet.rpc import IOCRSetup

        con = object.__new__(RPCCon)
        block = RPCCon._build_iocr_block(con, IOCR_TYPE_OUTPUT, 2, IOCRSetup(slots=[]))
        # FrameID field follows block header(6) + type(2) + ref(2) + lt(2) +
        # properties(4) + data_length(2)
        frame_id = struct.unpack(">H", block[18:20])[0]
        assert frame_id == 0xFFFF

    def test_input_frame_id_in_rtc1_range(self):
        from profinet.rpc import IOCRSetup

        con = object.__new__(RPCCon)
        block = RPCCon._build_iocr_block(con, IOCR_TYPE_INPUT, 1, IOCRSetup(slots=[]))
        frame_id = struct.unpack(">H", block[18:20])[0]
        assert 0xC000 <= frame_id <= 0xF7FF
