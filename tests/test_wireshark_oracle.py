"""Check request builders against Wireshark's PROFINET dissectors.

Each test captures the bytes the library really sends (mocked socket), has
tshark dissect them and asserts Wireshark's reading of the fields plus the
absence of malformed-packet or error-level expert items.
"""

from datetime import datetime
from unittest.mock import patch

import pytest

from profinet.rpc import IOCRSetup, IOSlot
from profinet.rt import (
    DATA_STATUS_PROVIDER_RUN,
    DATA_STATUS_STATE,
    DATA_STATUS_STATION_OK,
    DATA_STATUS_VALID,
    RTFrame,
    build_ethernet_frame,
)
from tests.wireshark_oracle import (
    CONTROLLER_MAC,
    DEVICE_MAC,
    capture_requests,
    dissect,
    expert_errors,
    ints,
    make_rpccon,
    requires_tshark,
    wrap_udp,
    write_pcap,
)

pytestmark = requires_tshark

IOCR_SETUP = IOCRSetup(
    slots=[
        IOSlot(slot=0, subslot=1, module_ident=0x1, submodule_ident=0x1),
        IOSlot(
            slot=1,
            subslot=1,
            input_length=4,
            output_length=4,
            module_ident=0x40,
            submodule_ident=0x140,
        ),
    ]
)


def _pcap_of(tmp_path, payloads):
    return write_pcap(tmp_path / "requests.pcap", [wrap_udp(p) for p in payloads])


@pytest.fixture
def rpc():
    with patch("profinet.rpc.socket"):
        con = make_rpccon()
        yield con


def _live(con):
    con.live = datetime.now()
    con.src_mac = CONTROLLER_MAC
    return con


class TestConnectRequest:
    def test_blocks_decode_without_errors(self, rpc, tmp_path):
        sent = capture_requests(
            rpc,
            lambda: rpc.connect(src_mac=CONTROLLER_MAC, with_alarm_cr=True, iocr_setup=IOCR_SETUP),
        )
        pcap = _pcap_of(tmp_path, sent[:1])

        assert expert_errors(pcap) == []
        (layers,) = dissect(
            pcap, ["pn_io.block_type", "@pn_io.artype_req", "pn_io.iocr_type", "pn_io.frame_id"]
        )
        block_types = ints(layers, "pn_io.block_type")
        assert block_types[0] == 0x0101  # ARBlockReq
        assert block_types.count(0x0102) == 2  # IOCRBlockReq input + output
        assert 0x0103 in block_types  # ExpectedSubmoduleBlockReq
        assert block_types[-1] == 0x0104  # AlarmCRBlockReq
        assert ints(layers, "@pn_io.artype_req") == [0x0001]  # IOCARSingle
        assert ints(layers, "pn_io.iocr_type") == [1, 2]  # Input, Output
        # Output CR: 0xFFFF lets the device pick the frame ID (p-net pf_cmdev.c)
        assert ints(layers, "pn_io.frame_id")[1] == 0xFFFF

    def test_without_iocr_or_alarm_cr(self, rpc, tmp_path):
        sent = capture_requests(rpc, lambda: rpc.connect(src_mac=CONTROLLER_MAC))
        pcap = _pcap_of(tmp_path, sent[:1])

        assert expert_errors(pcap) == []
        (layers,) = dissect(pcap, ["pn_io.block_type", "@pn_io.artype_req"])
        assert ints(layers, "pn_io.block_type") == [0x0101]
        assert ints(layers, "@pn_io.artype_req") == [0x0006]  # IOSAR (DeviceAccess)


class TestRecordRequests:
    def test_read(self, rpc, tmp_path):
        sent = capture_requests(_live(rpc), lambda: rpc.read(0, 0, 1, 0xAFF0))
        pcap = _pcap_of(tmp_path, sent[:1])

        assert expert_errors(pcap) == []
        (layers,) = dissect(
            pcap, ["pn_io.block_type", "pn_io.index", "pn_io.slot_nr", "pn_io.subslot_nr"]
        )
        assert ints(layers, "pn_io.block_type") == [0x0009]  # IODReadReqHeader
        assert ints(layers, "pn_io.index") == [0xAFF0]
        assert ints(layers, "pn_io.slot_nr") == [0]
        assert ints(layers, "pn_io.subslot_nr") == [1]

    def test_write(self, rpc, tmp_path):
        sent = capture_requests(_live(rpc), lambda: rpc.write(0, 1, 1, 0x0100, b"\x01\x02"))
        pcap = _pcap_of(tmp_path, sent[:1])

        assert expert_errors(pcap) == []
        (layers,) = dissect(pcap, ["pn_io.block_type", "pn_io.index", "pn_io.record_data_length"])
        assert ints(layers, "pn_io.block_type") == [0x0008]  # IODWriteReqHeader
        assert ints(layers, "pn_io.index") == [0x0100]
        assert ints(layers, "pn_io.record_data_length") == [2]

    @pytest.mark.xfail(
        strict=True,
        reason="write_multiple wraps the 0xE040 IODWriteReqHeader twice; fix proposed in #27",
    )
    def test_write_multiple(self, rpc, tmp_path):
        writes = [(1, 1, 0x0100, b"\x01\x02", 0), (1, 1, 0x0101, b"\x03", 0)]
        sent = capture_requests(_live(rpc), lambda: rpc.write_multiple(writes))
        pcap = _pcap_of(tmp_path, sent[:1])

        assert expert_errors(pcap) == []
        (layers,) = dissect(pcap, ["pn_io.block_type", "pn_io.index"])
        # Outer IODWriteReqHeader for 0xE040, then one header per write
        assert ints(layers, "pn_io.block_type") == [0x0008, 0x0008, 0x0008]
        assert ints(layers, "pn_io.index") == [0xE040, 0x0100, 0x0101]


class TestControlRequests:
    @pytest.mark.parametrize(
        ("method", "block_type", "flag"),
        [
            ("prm_begin", 0x0118, "pn_io.control_command.prmbegin"),
            ("prm_end", 0x0110, "pn_io.control_command.prmend"),
        ],
    )
    def test_control(self, rpc, tmp_path, method, block_type, flag):
        sent = capture_requests(_live(rpc), getattr(rpc, method))
        pcap = _pcap_of(tmp_path, sent[:1])

        assert expert_errors(pcap) == []
        (layers,) = dissect(pcap, ["pn_io.block_type", flag])
        assert ints(layers, "pn_io.block_type") == [block_type]
        assert ints(layers, flag) == [1]


class TestRTFrame:
    def test_output_data_status(self, tmp_path):
        status = (
            DATA_STATUS_STATE
            | DATA_STATUS_VALID
            | DATA_STATUS_PROVIDER_RUN
            | DATA_STATUS_STATION_OK
        )
        frame = RTFrame(
            frame_id=0xC001,
            cycle_counter=0x1234,
            data_status=status,
            transfer_status=0,
            payload=bytes(40),
        )
        pcap = write_pcap(
            tmp_path / "rt.pcap", [build_ethernet_frame(DEVICE_MAC, CONTROLLER_MAC, frame)]
        )

        assert expert_errors(pcap) == []
        (layers,) = dissect(
            pcap,
            [
                "pn_rt.frame_id",
                "pn_rt.cycle_counter",
                "pn_rt.ds_primary",
                "pn_rt.ds_redundancy",
                "pn_rt.ds_valid",
                "pn_rt.ds_operate",
                "pn_rt.ds_ok",
            ],
        )
        assert ints(layers, "pn_rt.frame_id") == [0xC001]
        assert ints(layers, "pn_rt.cycle_counter") == [0x1234]
        assert ints(layers, "pn_rt.ds_primary") == [1]
        assert ints(layers, "pn_rt.ds_redundancy") == [0]
        assert ints(layers, "pn_rt.ds_valid") == [1]
        assert ints(layers, "pn_rt.ds_operate") == [1]
        assert ints(layers, "pn_rt.ds_ok") == [1]
