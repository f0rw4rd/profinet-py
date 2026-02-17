"""Tests for profinet.protocol module."""

import pytest

from profinet.protocol import (
    EthernetHeader,
    EthernetVLANHeader,
    PNBlockHeader,
    PNDCPBlock,
    PNDCPBlockRequest,
    PNDCPHeader,
)


class TestEthernetHeader:
    """Test EthernetHeader packet structure."""

    def test_parse_ethernet_header(self):
        """Test parsing Ethernet header from bytes."""
        # dst(6) + src(6) + type(2) + payload
        data = (
            b"\x01\x02\x03\x04\x05\x06"  # dst
            + b"\x0a\x0b\x0c\x0d\x0e\x0f"  # src
            + b"\x88\x92"  # type (PROFINET)
            + b"\x00\x00"  # payload
        )

        pkt = EthernetHeader(data)

        assert pkt.dst == b"\x01\x02\x03\x04\x05\x06"
        assert pkt.src == b"\x0a\x0b\x0c\x0d\x0e\x0f"
        assert pkt.type == 0x8892

    def test_create_ethernet_header(self):
        """Test creating Ethernet header."""
        pkt = EthernetHeader(
            b"\x01\x02\x03\x04\x05\x06",
            b"\x0a\x0b\x0c\x0d\x0e\x0f",
            0x8892,
            payload=b"\x00\x00",
        )

        data = bytes(pkt)
        assert data[:6] == b"\x01\x02\x03\x04\x05\x06"
        assert data[6:12] == b"\x0a\x0b\x0c\x0d\x0e\x0f"
        assert data[12:14] == b"\x88\x92"


class TestEthernetVLANHeader:
    """Test EthernetVLANHeader packet structure."""

    def test_parse_vlan_header(self):
        """Test parsing VLAN tagged Ethernet header."""
        data = (
            b"\x01\x02\x03\x04\x05\x06"  # dst
            + b"\x0a\x0b\x0c\x0d\x0e\x0f"  # src
            + b"\x81\x00"  # tpid (VLAN ethertype)
            + b"\x00\x00"  # tci (VLAN ID/priority)
            + b"\x88\x92"  # type (inner type - PROFINET)
            + b"\x00"  # payload
        )

        pkt = EthernetVLANHeader(data)

        assert pkt.dst == b"\x01\x02\x03\x04\x05\x06"
        assert pkt.src == b"\x0a\x0b\x0c\x0d\x0e\x0f"
        assert pkt.tpid == 0x8100
        assert pkt.tci == 0x0000
        assert pkt.type == 0x8892


class TestPNDCPHeader:
    """Test PNDCPHeader packet structure."""

    def test_parse_dcp_header(self):
        """Test parsing DCP header."""
        data = (
            b"\xfe\xfe"  # frame_id (Identify)
            + b"\x05"  # service_id (Identify)
            + b"\x00"  # service_type (Request)
            + b"\x12\x34\x56\x78"  # xid
            + b"\x00\xc0"  # delay
            + b"\x00\x04"  # length
            + b"\xff\xff\x00\x00"  # payload
        )

        pkt = PNDCPHeader(data)

        assert pkt.frame_id == 0xFEFE
        assert pkt.service_id == 0x05
        assert pkt.service_type == 0x00
        assert pkt.xid == 0x12345678
        assert pkt.length == 4

    def test_dcp_header_constants(self):
        """Test DCP header constants."""
        assert PNDCPHeader.IDENTIFY == 0x05
        assert PNDCPHeader.GET == 0x03
        assert PNDCPHeader.SET == 0x04
        assert PNDCPHeader.REQUEST == 0x00
        assert PNDCPHeader.RESPONSE == 0x01


class TestPNDCPBlock:
    """Test PNDCPBlock packet structure."""

    def test_parse_dcp_block(self):
        """Test parsing DCP response block."""
        # DCP response block includes status field (2 bytes)
        # Structure: option(1) + suboption(1) + length(2) + status(2) + payload
        # Length includes status, so payload = length - 2 bytes
        data = (
            b"\x02"  # option (Device properties)
            + b"\x02"  # suboption (Name of station)
            + b"\x00\x0d"  # length (13 = 2 bytes status + 11 bytes name)
            + b"\x00\x00"  # status
            + b"test-device"  # payload (11 bytes)
        )

        pkt = PNDCPBlock(data)

        assert pkt.option == 0x02
        assert pkt.suboption == 0x02
        assert pkt.length == 13
        assert pkt.status == 0x0000
        assert pkt.payload == b"test-device"

    def test_dcp_block_constants(self):
        """Test DCP block type constants."""
        assert PNDCPBlock.NAME_OF_STATION == (0x02, 0x02)
        assert PNDCPBlock.IP_ADDRESS == (0x01, 0x02)
        assert PNDCPBlock.DEVICE_ID == (0x02, 0x03)


class TestPNBlockHeader:
    """Test PNBlockHeader packet structure."""

    def test_parse_block_header(self):
        """Test parsing block header."""
        data = (
            b"\x00\x08"  # block_type
            + b"\x00\x3c"  # block_length
            + b"\x01"  # block_version_high
            + b"\x00"  # block_version_low
        )

        pkt = PNBlockHeader(data)

        assert pkt.block_type == 0x0008
        assert pkt.block_length == 60
        assert pkt.block_version_high == 1
        assert pkt.block_version_low == 0

    def test_block_header_constants(self):
        """Test block header constants."""
        assert hasattr(PNBlockHeader, "IODReadRequestHeader")
        assert PNBlockHeader.IODReadRequestHeader == 0x0009


# =============================================================================
# Additional protocol packet tests
# =============================================================================

import struct

from profinet.protocol import (
    IOCRAPIObject,
    IPConfiguration,
    PNAlarmCRBlockReq,
    PNAlarmNotificationPDU,
    PNExpectedSubmoduleDataDescription,
    PNInM0,
    PNInM1,
    PNInM2,
    PNInM3,
    PNInM4,
    PNInM5,
    PNInM6,
    PNInM15,
    PNIOCRBlockRes,
    PNIODHeader,
    PNIODWriteReq,
    PNIODWriteRes,
    PNNRDData,
    PNRPCHeader,
    PNRTAHeader,
)


class TestMakePacketReprStr:
    """Test __repr__ and __str__ methods on make_packet classes."""

    def test_ethernet_header_repr(self):
        """Test EthernetHeader repr shows fields."""
        data = b"\x01\x02\x03\x04\x05\x06" + b"\x0a\x0b\x0c\x0d\x0e\x0f" + b"\x88\x92" + b"\x00\x00"
        pkt = EthernetHeader(data)
        r = repr(pkt)
        assert "EthernetHeader" in r
        assert "dst=" in r
        assert "src=" in r
        assert "type=" in r

    def test_ethernet_header_str(self):
        """Test EthernetHeader str shows formatted fields."""
        data = b"\x01\x02\x03\x04\x05\x06" + b"\x0a\x0b\x0c\x0d\x0e\x0f" + b"\x88\x92" + b"\x00\x00"
        pkt = EthernetHeader(data)
        s = str(pkt)
        assert "EthernetHeader" in s
        assert "dst:" in s
        assert "src:" in s

    def test_ethernet_header_len(self):
        """Test EthernetHeader __len__ returns total size."""
        data = (
            b"\x01\x02\x03\x04\x05\x06"
            + b"\x0a\x0b\x0c\x0d\x0e\x0f"
            + b"\x88\x92"
            + b"\xde\xad"  # 2 bytes payload
        )
        pkt = EthernetHeader(data)
        assert len(pkt) == 16  # 14 header + 2 payload

    def test_pn_block_header_repr(self):
        """Test PNBlockHeader repr (no payload class)."""
        data = struct.pack(">HHBB", 0x0020, 0x003C, 0x01, 0x00)
        pkt = PNBlockHeader(data)
        r = repr(pkt)
        assert "PNBlockHeader" in r


class TestMakePacketSerialization:
    """Test serialization roundtrip for make_packet classes."""

    def test_ethernet_header_roundtrip(self):
        """Test EthernetHeader parse -> serialize roundtrip."""
        original = (
            b"\x01\x02\x03\x04\x05\x06" + b"\x0a\x0b\x0c\x0d\x0e\x0f" + b"\x88\x92" + b"\xde\xad"
        )
        pkt = EthernetHeader(original)
        serialized = bytes(pkt)
        assert serialized == original

    def test_pn_dcp_header_roundtrip(self):
        """Test PNDCPHeader parse -> serialize roundtrip."""
        original = (
            b"\xfe\xfe"  # frame_id
            + b"\x05"  # service_id
            + b"\x00"  # service_type
            + b"\x12\x34\x56\x78"  # xid
            + b"\x00\xc0"  # resp/delay
            + b"\x00\x04"  # length
            + b"\xff\xff\x00\x00"  # payload
        )
        pkt = PNDCPHeader(original)
        serialized = bytes(pkt)
        assert serialized == original

    def test_pn_dcp_block_request_roundtrip(self):
        """Test PNDCPBlockRequest parse -> serialize roundtrip."""
        original = (
            b"\x02"  # option
            + b"\x02"  # suboption
            + b"\x00\x04"  # length
            + b"\x74\x65\x73\x74"  # payload "test"
        )
        pkt = PNDCPBlockRequest(original)
        serialized = bytes(pkt)
        assert serialized == original

    def test_pn_dcp_block_roundtrip(self):
        """Test PNDCPBlock parse -> serialize roundtrip."""
        original = (
            b"\x02\x02"  # option, suboption
            + b"\x00\x06"  # length
            + b"\x00\x00"  # status
            + b"\x74\x65\x73\x74"  # payload "test"
        )
        pkt = PNDCPBlock(original)
        serialized = bytes(pkt)
        assert serialized == original

    def test_pn_block_header_serialization(self):
        """Test PNBlockHeader serialization."""
        pkt = PNBlockHeader(0x0020, 0x003C, 0x01, 0x00)
        data = bytes(pkt)
        assert data == struct.pack(">HHBB", 0x0020, 0x003C, 0x01, 0x00)


class TestMakePacketInsufficientData:
    """Test make_packet error handling for insufficient data."""

    def test_ethernet_header_too_short(self):
        """Test EthernetHeader raises on short data."""
        with pytest.raises(ValueError, match="insufficient data"):
            EthernetHeader(b"\x00" * 10)

    def test_pn_dcp_header_too_short(self):
        """Test PNDCPHeader raises on short data."""
        with pytest.raises(ValueError, match="insufficient data"):
            PNDCPHeader(b"\x00" * 5)

    def test_pn_block_header_too_short(self):
        """Test PNBlockHeader raises on short data."""
        with pytest.raises(ValueError, match="insufficient data"):
            PNBlockHeader(b"\x00" * 3)


class TestPNRPCHeader:
    """Test PNRPCHeader packet structure."""

    def test_constants(self):
        """Test RPC header constants."""
        assert PNRPCHeader.REQUEST == 0x00
        assert PNRPCHeader.RESPONSE == 0x02
        assert PNRPCHeader.FAULT == 0x03
        assert PNRPCHeader.CONNECT == 0x00
        assert PNRPCHeader.RELEASE == 0x01
        assert PNRPCHeader.READ == 0x02
        assert PNRPCHeader.WRITE == 0x03
        assert PNRPCHeader.CONTROL == 0x04

    def test_interface_uuids(self):
        """Test interface UUID constants are 16 bytes."""
        assert len(PNRPCHeader.IFACE_UUID_DEVICE) == 16
        assert len(PNRPCHeader.IFACE_UUID_CONTROLLER) == 16
        assert len(PNRPCHeader.IFACE_UUID_SUPERVISOR) == 16
        assert len(PNRPCHeader.IFACE_UUID_PARAMSERVER) == 16

    def test_object_uuid_prefix(self):
        """Test object UUID prefix is 10 bytes."""
        assert len(PNRPCHeader.OBJECT_UUID_PREFIX) == 10

    def test_parse_rpc_header(self):
        """Test parsing RPC header from bytes."""
        # Build minimal RPC header (80 bytes)
        data = bytearray(80)
        data[0] = 0x04  # version
        data[1] = 0x02  # packet_type (RESPONSE)
        data[2] = 0x20  # flags1
        data[3] = 0x00  # flags2
        # drep (3 bytes) at offset 4
        # serial_high at offset 7
        # object_uuid (16 bytes) at offset 8
        # interface_uuid (16 bytes) at offset 24
        # activity_uuid (16 bytes) at offset 40
        # remaining fields...

        pkt = PNRPCHeader(bytes(data))
        assert pkt.version == 0x04
        assert pkt.packet_type == 0x02


class TestPNNRDData:
    """Test PNNRDData packet structure."""

    def test_parse_nrd_data(self):
        """Test parsing NRD data header."""
        data = struct.pack(
            ">IIIII",
            0x00000000,  # args_maximum_status
            0x00000100,  # args_length
            0x00000100,  # maximum_count
            0x00000000,  # offset
            0x00000100,  # actual_count
        )
        pkt = PNNRDData(data)
        assert pkt.args_maximum_status == 0
        assert pkt.args_length == 256
        assert pkt.actual_count == 256

    def test_nrd_data_roundtrip(self):
        """Test NRD data serialization roundtrip."""
        data = struct.pack(">IIIII", 0, 128, 128, 0, 128)
        pkt = PNNRDData(data)
        assert bytes(pkt) == data


class TestPNIODHeader:
    """Test PNIODHeader packet structure."""

    def test_parse_iod_header(self):
        """Test parsing IOD header."""
        data = bytearray(64)
        # block_header (6 bytes)
        struct.pack_into(">HHBB", data, 0, 0x0009, 60, 1, 0)
        # sequence_number at offset 6
        struct.pack_into(">H", data, 6, 1)
        # ar_uuid (16 bytes) at offset 8
        # api at offset 24
        struct.pack_into(">I", data, 24, 0)
        # slot at offset 28
        struct.pack_into(">H", data, 28, 0)
        # subslot at offset 30
        struct.pack_into(">H", data, 30, 1)
        # padding1 at offset 32
        # index at offset 34
        struct.pack_into(">H", data, 34, 0xAFF0)
        # length at offset 36
        struct.pack_into(">I", data, 36, 64)

        pkt = PNIODHeader(bytes(data))
        assert pkt.sequence_number == 1
        assert pkt.api == 0
        assert pkt.slot == 0
        assert pkt.subslot == 1
        assert pkt.index == 0xAFF0
        assert pkt.length == 64


class TestPNInMStructures:
    """Test I&M packet structures."""

    def test_pnin_m0_idx(self):
        """Test PNInM0 IDX constant."""
        assert PNInM0.IDX == 0xAFF0

    def test_pnin_m1_idx(self):
        """Test PNInM1 IDX constant."""
        assert PNInM1.IDX == 0xAFF1

    def test_pnin_m2_idx(self):
        """Test PNInM2 IDX constant."""
        assert PNInM2.IDX == 0xAFF2

    def test_pnin_m3_idx(self):
        """Test PNInM3 IDX constant."""
        assert PNInM3.IDX == 0xAFF3

    def test_pnin_m4_idx(self):
        """Test PNInM4 IDX constant."""
        assert PNInM4.IDX == 0xAFF4

    def test_pnin_m5_idx(self):
        """Test PNInM5 IDX constant."""
        assert PNInM5.IDX == 0xAFF5

    def test_pnin_m6_idx(self):
        """Test PNInM6 (reserved) IDX constant."""
        assert PNInM6.IDX == 0xAFF6

    def test_pnin_m15_idx(self):
        """Test PNInM15 (reserved) IDX constant."""
        assert PNInM15.IDX == 0xAFFF

    def test_parse_pnin_m0(self):
        """Test parsing PNInM0 structure."""
        data = bytearray(64)
        # block_header (6 bytes)
        struct.pack_into(">HHBB", data, 0, 0x0020, 58, 1, 0)
        # vendor_id_high, vendor_id_low
        data[6] = 0x00
        data[7] = 0x2A
        # order_id (20 bytes) at offset 8
        order_id = b"6ES7 214-1AG40-0XB0"
        data[8 : 8 + len(order_id)] = order_id
        # serial_number (16 bytes) at offset 28
        serial = b"S V-A6B205082016"
        data[28 : 28 + len(serial)] = serial

        pkt = PNInM0(bytes(data))
        assert pkt.vendor_id_high == 0x00
        assert pkt.vendor_id_low == 0x2A

    def test_parse_pnin_m1(self):
        """Test parsing PNInM1 structure."""
        data = bytearray(60)
        # block_header (6 bytes)
        struct.pack_into(">HHBB", data, 0, 0x0021, 54, 1, 0)
        # tag_function (32 bytes) at offset 6
        tag_func = b"Motor Control Unit"
        data[6 : 6 + len(tag_func)] = tag_func
        # tag_location (22 bytes) at offset 38

        pkt = PNInM1(bytes(data))
        assert b"Motor Control Unit" in pkt.im_tag_function

    def test_parse_pnin_m2(self):
        """Test parsing PNInM2 structure."""
        data = bytearray(22)
        struct.pack_into(">HHBB", data, 0, 0x0022, 16, 1, 0)
        date_str = b"2024-01-15 10:30"
        data[6 : 6 + len(date_str)] = date_str

        pkt = PNInM2(bytes(data))
        assert b"2024-01-15" in pkt.im_date

    def test_parse_pnin_m3(self):
        """Test parsing PNInM3 structure."""
        data = bytearray(60)
        struct.pack_into(">HHBB", data, 0, 0x0023, 54, 1, 0)
        desc = b"Test descriptor"
        data[6 : 6 + len(desc)] = desc

        pkt = PNInM3(bytes(data))
        assert b"Test descriptor" in pkt.im_descriptor

    def test_parse_pnin_m5(self):
        """Test parsing PNInM5 structure."""
        data = bytearray(70)
        struct.pack_into(">HHBB", data, 0, 0x0025, 64, 1, 0)
        annotation = b"Production line 4, Station 12"
        data[6 : 6 + len(annotation)] = annotation

        pkt = PNInM5(bytes(data))
        assert b"Production line 4" in pkt.im_annotation


class TestIPConfiguration:
    """Test IPConfiguration namedtuple."""

    def test_str_output(self):
        """Test IPConfiguration __str__ format."""
        ip_conf = IPConfiguration("192.168.1.1", "255.255.255.0", "192.168.1.254")
        output = str(ip_conf)
        assert "192.168.1.1" in output
        assert "255.255.255.0" in output
        assert "192.168.1.254" in output
        assert "IP Configuration" in output

    def test_fields(self):
        """Test IPConfiguration field access."""
        ip_conf = IPConfiguration("10.0.0.1", "255.0.0.0", "10.0.0.254")
        assert ip_conf.address == "10.0.0.1"
        assert ip_conf.netmask == "255.0.0.0"
        assert ip_conf.gateway == "10.0.0.254"


class TestPNDCPBlockRequestParseIP:
    """Test PNDCPBlockRequest.parse_ip method."""

    def test_parse_ip(self):
        """Test parsing IP configuration from block payload."""
        ip_payload = (
            b"\xc0\xa8\x01\x01"  # 192.168.1.1
            + b"\xff\xff\xff\x00"  # 255.255.255.0
            + b"\xc0\xa8\x01\xfe"  # 192.168.1.254
        )
        pkt = PNDCPBlockRequest(0x01, 0x02, len(ip_payload), payload=ip_payload)
        ip_conf = pkt.parse_ip()
        assert ip_conf.address == "192.168.1.1"
        assert ip_conf.netmask == "255.255.255.0"
        assert ip_conf.gateway == "192.168.1.254"


class TestPNDCPBlockParseIP:
    """Test PNDCPBlock.parse_ip method."""

    def test_parse_ip(self):
        """Test parsing IP from DCP response block."""
        data = (
            b"\x01\x02"  # option, suboption
            + b"\x00\x0e"  # length (14 = 2 status + 12 payload)
            + b"\x00\x00"  # status
            + b"\xc0\xa8\x01\x01"  # 192.168.1.1
            + b"\xff\xff\xff\x00"  # 255.255.255.0
            + b"\xc0\xa8\x01\xfe"  # 192.168.1.254
        )
        pkt = PNDCPBlock(data)
        ip_conf = pkt.parse_ip()
        assert ip_conf.address == "192.168.1.1"
        assert ip_conf.netmask == "255.255.255.0"
        assert ip_conf.gateway == "192.168.1.254"


class TestPNDCPBlockExtendedConstants:
    """Test extended PNDCPBlock constants."""

    def test_all_block_constants(self):
        """Test all PNDCPBlock option/suboption constants."""
        assert PNDCPBlock.IP_MAC == (1, 1)
        assert PNDCPBlock.IP_ADDRESS == (1, 2)
        assert PNDCPBlock.IP_FULL_SUITE == (1, 3)
        assert PNDCPBlock.DEVICE_TYPE == (2, 1)
        assert PNDCPBlock.NAME_OF_STATION == (2, 2)
        assert PNDCPBlock.DEVICE_ID == (2, 3)
        assert PNDCPBlock.DEVICE_ROLE == (2, 4)
        assert PNDCPBlock.DEVICE_OPTIONS == (2, 5)
        assert PNDCPBlock.DEVICE_ALIAS == (2, 6)
        assert PNDCPBlock.DEVICE_INSTANCE == (2, 7)
        assert PNDCPBlock.DEVICE_OEM_ID == (2, 8)
        assert PNDCPBlock.ALL == (0xFF, 0xFF)


class TestPNDCPHeaderExtendedConstants:
    """Test extended PNDCPHeader constants."""

    def test_hello_constant(self):
        """Test PNDCPHeader HELLO constant."""
        assert PNDCPHeader.HELLO == 6

    def test_response_unsupported(self):
        """Test RESPONSE_UNSUPPORTED constant."""
        assert PNDCPHeader.RESPONSE_UNSUPPORTED == 5


class TestIOCRAPIObject:
    """Test IOCRAPIObject structure."""

    def test_parse(self):
        """Test parsing IOCRAPIObject."""
        data = struct.pack(">HHH", 0, 1, 0x0020)
        pkt = IOCRAPIObject(data)
        assert pkt.slot_number == 0
        assert pkt.subslot_number == 1
        assert pkt.frame_offset == 0x0020

    def test_create(self):
        """Test creating IOCRAPIObject."""
        pkt = IOCRAPIObject(0, 1, 0x0020)
        data = bytes(pkt)
        assert struct.unpack(">HHH", data) == (0, 1, 0x0020)


class TestPNIOCRBlockRes:
    """Test PNIOCRBlockRes structure."""

    def test_block_type_constant(self):
        """Test BLOCK_TYPE constant."""
        assert PNIOCRBlockRes.BLOCK_TYPE == 0x8102


class TestPNAlarmCRBlockReq:
    """Test PNAlarmCRBlockReq structure."""

    def test_block_type_constant(self):
        """Test BLOCK_TYPE constant."""
        assert PNAlarmCRBlockReq.BLOCK_TYPE == 0x0103

    def test_default_constants(self):
        """Test default constants."""
        assert PNAlarmCRBlockReq.DEFAULT_RTA_TIMEOUT_FACTOR == 1
        assert PNAlarmCRBlockReq.DEFAULT_RTA_RETRIES == 3
        assert PNAlarmCRBlockReq.DEFAULT_MAX_ALARM_DATA_LENGTH == 200
        assert PNAlarmCRBlockReq.DEFAULT_TAG_HEADER_HIGH == 0xC000
        assert PNAlarmCRBlockReq.DEFAULT_TAG_HEADER_LOW == 0xA000


class TestPNAlarmNotificationPDU:
    """Test PNAlarmNotificationPDU structure."""

    def test_block_alarm_constants(self):
        """Test alarm block type constants."""
        assert PNAlarmNotificationPDU.BLOCK_ALARM_HIGH == 0x0001
        assert PNAlarmNotificationPDU.BLOCK_ALARM_LOW == 0x0002
        assert PNAlarmNotificationPDU.BLOCK_ALARM_ACK_HIGH == 0x8001
        assert PNAlarmNotificationPDU.BLOCK_ALARM_ACK_LOW == 0x8002


class TestPNRTAHeader:
    """Test PNRTAHeader structure."""

    def test_rta_type_constants(self):
        """Test RTA type constants."""
        assert PNRTAHeader.RTA_TYPE_DATA == 0x01
        assert PNRTAHeader.RTA_TYPE_NACK == 0x02
        assert PNRTAHeader.RTA_TYPE_ACK == 0x03
        assert PNRTAHeader.RTA_TYPE_ERR == 0x04

    def test_version_constants(self):
        """Test RTA version constants."""
        assert PNRTAHeader.VERSION_1 == 0x01
        assert PNRTAHeader.VERSION_2 == 0x02


class TestPNExpectedSubmoduleDataDescription:
    """Test PNExpectedSubmoduleDataDescription structure."""

    def test_parse(self):
        """Test parsing expected submodule data description."""
        data = struct.pack(">HHBB", 1, 10, 1, 1)
        pkt = PNExpectedSubmoduleDataDescription(data)
        assert pkt.data_description == 1
        assert pkt.submodule_data_length == 10
        assert pkt.length_iocs == 1
        assert pkt.length_iops == 1

    def test_create_and_serialize(self):
        """Test creating and serializing."""
        pkt = PNExpectedSubmoduleDataDescription(2, 20, 1, 1)
        data = bytes(pkt)
        assert struct.unpack(">HHBB", data) == (2, 20, 1, 1)


class TestPNIODWriteReq:
    """Test PNIODWriteReq structure."""

    def test_block_type_constant(self):
        """Test BLOCK_TYPE constant."""
        assert PNIODWriteReq.BLOCK_TYPE == 0x0008


class TestPNIODWriteRes:
    """Test PNIODWriteRes structure."""

    def test_block_type_constant(self):
        """Test BLOCK_TYPE constant."""
        assert PNIODWriteRes.BLOCK_TYPE == 0x8008
