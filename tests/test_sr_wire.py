"""Wire-level checks for System Redundancy (IOCARSR) support.

Sources for the expected values:

- Wireshark plugins/epan/profinet/packet-dcerpc-pn-io.c (tshark 4.4):
  ARType 0x0020 IOCARSR; SRInfoBlock 0x010A v1.0 = RedundancyDataHoldFactor
  u16 + SRProperties u32; SubmoduleListBlock 0x0119 v1.0 = NumberOfEntries
  u16 + N x (API u32, Slot u16, Subslot u16); IOCARSR ARUUID Selector
  ARnumber mask 0x0007 (values 1..4), ARresource mask 0x0018 (2 = two ARs);
  RedundancyDataHoldFactor 0..2 reserved.
- Wireshark packet-pn-rt.c: output CR DataStatus 0x05 = Primary Request,
  0x04 = Backup Request; the Redundancy bit is fixed to 0 on output CRs.
- Captured IOCARSR Connect request: cisagov PROFINET IO CM sample
  ``cisagov_profinet_io_cm_connect.pcapng`` (sha256 9bd5caa7...77bfd4),
  frame 63, 192.168.0.1 -> 192.168.0.2. Vectors below are copied from it.

The module skips until the library has SR support (``SRInfoConfig``).
"""

from datetime import datetime
from unittest.mock import patch

import pytest

import profinet.rpc as rpc_module
from profinet.exceptions import ValidationError

if not hasattr(rpc_module, "SRInfoConfig"):
    pytest.skip("library has no System Redundancy support", allow_module_level=True)

from profinet.rpc import IOCRSetup, IOSlot, SRInfoConfig  # noqa: E402
from profinet.rt import RTFrame, build_ethernet_frame  # noqa: E402
from tests.wireshark_oracle import (  # noqa: E402
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

# cisagov_profinet_io_cm_connect.pcapng frame 63
CAPTURE_AR_UUID = bytes.fromhex("aa57bb2d2bbd674d835c2ac33a800011")
CAPTURE_DISCRIMINATOR = CAPTURE_AR_UUID[:6]
CAPTURE_CONFIG_ID = CAPTURE_AR_UUID[6:14]
CAPTURE_SR_INFO_BLOCK = bytes.fromhex("010a00080100009600000000")  # RDHF 150, SRProperties 0
CAPTURE_AR_PROPERTIES = 0x60000011

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


def _capture_sr(ar_number: int = 1) -> SRInfoConfig:
    return SRInfoConfig(
        ar_number=ar_number,
        discriminator=CAPTURE_DISCRIMINATOR,
        config_id=CAPTURE_CONFIG_ID,
        redundancy_data_hold_factor=150,
    )


@pytest.fixture
def rpc():
    with patch("profinet.rpc.socket"):
        yield make_rpccon()


class TestCaptureVectors:
    def test_sr_info_block_bytes(self, rpc):
        assert rpc._build_sr_info_block(_capture_sr()) == CAPTURE_SR_INFO_BLOCK

    def test_ar_uuid_selector(self):
        assert _capture_sr(1).ar_uuid == CAPTURE_AR_UUID

    def test_second_ar_differs_only_in_ar_number(self):
        assert _capture_sr(2).ar_uuid == CAPTURE_AR_UUID[:-2] + bytes.fromhex("0012")


class TestSpecRanges:
    @pytest.mark.parametrize("ar_number", [0, 5, 7])
    def test_ar_number_outside_1_to_4_rejected(self, ar_number):
        with pytest.raises(ValidationError):
            SRInfoConfig(ar_number=ar_number)

    @pytest.mark.parametrize("rdhf", [0, 1, 2])
    def test_reserved_redundancy_data_hold_factor_rejected(self, rdhf):
        with pytest.raises(ValidationError):
            SRInfoConfig(redundancy_data_hold_factor=rdhf)


@requires_tshark
class TestConnectDecode:
    @pytest.mark.parametrize("ar_number", [1, 2])
    def test_iocarsr_connect(self, rpc, tmp_path, ar_number):
        sent = capture_requests(
            rpc,
            lambda: rpc.connect(
                src_mac=CONTROLLER_MAC,
                with_alarm_cr=True,
                iocr_setup=IOCR_SETUP,
                sr_info=_capture_sr(ar_number),
            ),
        )
        pcap = write_pcap(tmp_path / "connect.pcap", [wrap_udp(sent[0])])

        assert expert_errors(pcap) == []
        (layers,) = dissect(
            pcap,
            [
                "@pn_io.artype_req",
                "pn_io.block_type",
                "pn_io.ar_arnumber",
                "pn_io.ar_arresource",
                "pn_io.RedundancyDataHoldFactor",
                "pn_io.sr_properties",
            ],
        )
        assert ints(layers, "@pn_io.artype_req") == [0x0020]
        assert 0x010A in ints(layers, "pn_io.block_type")
        assert ints(layers, "pn_io.ar_arnumber") == [ar_number]
        assert ints(layers, "pn_io.ar_arresource") == [2]
        assert ints(layers, "pn_io.RedundancyDataHoldFactor") == [150]
        assert ints(layers, "pn_io.sr_properties") == [0]

    def test_ar_properties_match_capture(self, rpc, tmp_path):
        sent = capture_requests(
            rpc,
            lambda: rpc.connect(
                src_mac=CONTROLLER_MAC, iocr_setup=IOCR_SETUP, sr_info=_capture_sr()
            ),
        )
        pcap = write_pcap(tmp_path / "connect.pcap", [wrap_udp(sent[0])])

        (layers,) = dissect(pcap, ["pn_io.ar_properties"])
        # StartupMode Advanced (bit 30) + CombinedObjectContainer (bit 29),
        # as in the captured IOCARSR Connect
        assert ints(layers, "pn_io.ar_properties") == [CAPTURE_AR_PROPERTIES]


@requires_tshark
class TestPrmBeginDecode:
    def test_submodule_list_block(self, rpc, tmp_path):
        rpc.live = datetime.now()
        rpc.src_mac = CONTROLLER_MAC
        rpc._iocr_setup = IOCR_SETUP
        sent = capture_requests(rpc, rpc.prm_begin)
        pcap = write_pcap(tmp_path / "prm_begin.pcap", [wrap_udp(sent[0])])

        assert expert_errors(pcap) == []
        (layers,) = dissect(
            pcap,
            [
                "pn_io.block_type",
                "pn_io.control_command.prmbegin",
                "pn_io.SubmoduleListEntries",
                "pn_io.slot_nr",
                "pn_io.subslot_nr",
            ],
        )
        assert ints(layers, "pn_io.block_type") == [0x0118, 0x0119]
        assert ints(layers, "pn_io.control_command.prmbegin") == [1]
        assert ints(layers, "pn_io.SubmoduleListEntries") == [2]
        assert ints(layers, "pn_io.slot_nr") == [0, 1]
        assert ints(layers, "pn_io.subslot_nr") == [1, 1]


@requires_tshark
class TestOutputDataStatus:
    @pytest.mark.parametrize(("primary", "low_bits"), [(True, 0x05), (False, 0x04)])
    def test_primary_backup_request(self, tmp_path, primary, low_bits):
        from tests.test_cyclic import make_controller

        status = make_controller(primary=primary)._build_data_status()
        assert status & 0x07 == low_bits

        frame = RTFrame(
            frame_id=0xC001,
            cycle_counter=1,
            data_status=status,
            transfer_status=0,
            payload=bytes(40),
        )
        pcap = write_pcap(
            tmp_path / "rt.pcap", [build_ethernet_frame(DEVICE_MAC, CONTROLLER_MAC, frame)]
        )

        assert expert_errors(pcap) == []
        (layers,) = dissect(pcap, ["pn_rt.ds_primary", "pn_rt.ds_redundancy", "pn_rt.ds_valid"])
        assert ints(layers, "pn_rt.ds_primary") == [int(primary)]
        assert ints(layers, "pn_rt.ds_redundancy") == [0]
        assert ints(layers, "pn_rt.ds_valid") == [1]


class TestSubmoduleListBlockParse:
    def _parse(self, data):
        from profinet.blocks import parse_submodule_list_block

        return parse_submodule_list_block(data)

    def test_round_trip(self):
        from profinet.blocks import SubmoduleListBlock

        block = SubmoduleListBlock().add_entry(0, 1, 1).add_entry(0x3A00, 1, 4)
        parsed = self._parse(block.to_bytes())
        assert [(e.api, e.slot_number, e.subslot_number) for e in parsed.entries] == [
            (0, 1, 1),
            (0x3A00, 1, 4),
        ]

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            bytes.fromhex("0119"),
            bytes.fromhex("0119000c0100"),  # header only, count missing
            bytes.fromhex("0119000c01000001000000"),  # count 1, entry truncated
            bytes.fromhex("011900040100ffff"),  # count larger than block
        ],
    )
    def test_truncated_or_inconsistent_rejected(self, data):
        from profinet.exceptions import ProfinetError

        with pytest.raises((ProfinetError, ValueError)):
            self._parse(data)
