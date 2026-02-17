"""
PROFINET protocol packet definitions.

Defines packet structures for:
- DCP (Discovery and Configuration Protocol)
- DCE/RPC (Remote Procedure Call)
- PNIO (PROFINET IO) data blocks

"""

from __future__ import annotations

from collections import namedtuple
from typing import Tuple

from .util import decode_bytes, mac2s, make_packet, s2ip

# =============================================================================
# DCP - Discovery and Configuration Protocol
# =============================================================================

EthernetHeader = make_packet(
    "EthernetHeader",
    (
        ("dst", ("6s", mac2s)),
        ("src", ("6s", mac2s)),
        ("type", ("H", "0x%04X")),
    ),
)

EthernetVLANHeader = make_packet(
    "EthernetVLANHeader",
    (
        ("dst", ("6s", mac2s)),
        ("src", ("6s", mac2s)),
        ("tpid", ("H", "0x%04X")),
        ("tci", ("H", "0x%04X")),
        ("type", ("H", "0x%04X")),
    ),
)

PNDCPHeader = make_packet(
    "PNDCPHeader",
    (
        ("frame_id", ("H", "0x%04X")),
        ("service_id", "B"),
        ("service_type", "B"),
        ("xid", ("I", "0x%08X")),
        ("resp", "H"),
        ("length", "H"),
    ),
    statics={
        "ETHER_TYPE": 0x8892,
        # Service IDs
        "GET": 3,
        "SET": 4,
        "IDENTIFY": 5,
        "HELLO": 6,
        # Service Types
        "REQUEST": 0,
        "RESPONSE": 1,
        "RESPONSE_UNSUPPORTED": 5,
    },
)


class IPConfiguration(namedtuple("IPConfiguration", ["address", "netmask", "gateway"])):
    """IP configuration data from DCP response."""

    def __str__(self) -> str:
        return (
            f"IP Configuration\n"
            f"  Address: {self.address}\n"
            f"  Netmask: {self.netmask}\n"
            f"  Gateway: {self.gateway}"
        )


class PNDCPBlockRequest(
    make_packet(
        "PNDCPBlockRequest",
        (
            ("option", "B"),
            ("suboption", "B"),
            ("length", "H"),
        ),
        payload_size_field="length",
    )
):
    """DCP request block."""

    def parse_ip(self) -> IPConfiguration:
        """Parse IP configuration from payload."""
        return IPConfiguration(
            s2ip(self.payload[0:4]),
            s2ip(self.payload[4:8]),
            s2ip(self.payload[8:12]),
        )


class PNDCPBlock(
    make_packet(
        "PNDCPBlock",
        (
            ("option", "B"),
            ("suboption", "B"),
            ("length", "H"),
            ("status", "H"),
        ),
        payload_size_field="length",
        payload_offset=-2,
    )
):
    """DCP response block."""

    # Block option/suboption constants
    # IP Option (0x01)
    IP_MAC: Tuple[int, int] = (1, 1)
    IP_ADDRESS: Tuple[int, int] = (1, 2)
    IP_FULL_SUITE: Tuple[int, int] = (1, 3)
    # Device Option (0x02)
    DEVICE_TYPE: Tuple[int, int] = (2, 1)  # Type of Station / Manufacturer specific
    NAME_OF_STATION: Tuple[int, int] = (2, 2)
    DEVICE_ID: Tuple[int, int] = (2, 3)  # Vendor ID + Device ID
    DEVICE_ROLE: Tuple[int, int] = (2, 4)  # IO-Device, IO-Controller, etc.
    DEVICE_OPTIONS: Tuple[int, int] = (2, 5)  # Supported options list
    DEVICE_ALIAS: Tuple[int, int] = (2, 6)  # Alias name
    DEVICE_INSTANCE: Tuple[int, int] = (2, 7)  # Device instance high/low
    DEVICE_OEM_ID: Tuple[int, int] = (2, 8)  # OEM Device ID
    # All selector
    ALL: Tuple[int, int] = (0xFF, 0xFF)

    def parse_ip(self) -> IPConfiguration:
        """Parse IP configuration from payload."""
        return IPConfiguration(
            s2ip(self.payload[0:4]),
            s2ip(self.payload[4:8]),
            s2ip(self.payload[8:12]),
        )


# =============================================================================
# DCE/RPC - Remote Procedure Call
# =============================================================================

# PROFINET UUID suffix
_UUID = [0x6C, 0x97, 0x11, 0xD1, 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D]

PNRPCHeader = make_packet(
    "PNRPCHeader",
    (
        ("version", "B"),
        ("packet_type", "B"),
        ("flags1", "B"),
        ("flags2", "B"),
        ("drep", "3s"),  # Data representation
        ("serial_high", "B"),
        ("object_uuid", "16s"),
        ("interface_uuid", "16s"),
        ("activity_uuid", "16s"),
        ("server_boot_time", "I"),
        ("interface_version", "I"),
        ("sequence_number", "I"),
        ("operation_number", "H"),
        ("interface_hint", "H"),
        ("activity_hint", "H"),
        ("length_of_body", "H"),
        ("fragment_number", "H"),
        ("authentication_protocol", "B"),
        ("serial_low", "B"),
    ),
    statics={
        # Packet types
        "REQUEST": 0x00,
        "PING": 0x01,
        "RESPONSE": 0x02,
        "FAULT": 0x03,
        "WORKING": 0x04,
        "PONG": 0x05,
        "REJECT": 0x06,
        "ACK": 0x07,
        "CANCEL": 0x08,
        "FRAG_ACK": 0x09,
        "CANCEL_ACK": 0x0A,
        # Operation numbers
        "CONNECT": 0x00,
        "RELEASE": 0x01,
        "READ": 0x02,
        "WRITE": 0x03,
        "CONTROL": 0x04,
        "IMPLICIT_READ": 0x05,
        # Interface UUIDs (big-endian byte order, matching drep=0x00 in _create_rpc)
        "IFACE_UUID_DEVICE": bytes([0xDE, 0xA0, 0x00, 0x01] + _UUID),
        "IFACE_UUID_CONTROLLER": bytes([0xDE, 0xA0, 0x00, 0x02] + _UUID),
        "IFACE_UUID_SUPERVISOR": bytes([0xDE, 0xA0, 0x00, 0x03] + _UUID),
        "IFACE_UUID_PARAMSERVER": bytes([0xDE, 0xA0, 0x00, 0x04] + _UUID),
        # Object UUID prefix
        "OBJECT_UUID_PREFIX": bytes([0xDE, 0xA0, 0x00, 0x00, 0x6C, 0x97, 0x11, 0xD1, 0x82, 0x71]),
    },
)


PNNRDData = make_packet(
    "PNNRDData",
    (
        ("args_maximum_status", "I"),
        ("args_length", "I"),
        ("maximum_count", "I"),
        ("offset", "I"),
        ("actual_count", "I"),
    ),
)


PNIODHeader = make_packet(
    "PNIODHeader",
    (
        ("block_header", "6s"),
        ("sequence_number", "H"),
        ("ar_uuid", "16s"),
        ("api", "I"),
        ("slot", "H"),
        ("subslot", "H"),
        ("padding1", "H"),
        ("index", "H"),
        ("length", "I"),
        ("target_ar_uuid", "16s"),
        ("padding2", "8s"),
    ),
)


PNBlockHeader = make_packet(
    "PNBlockHeader",
    (
        ("block_type", "H"),
        ("block_length", "H"),
        ("block_version_high", "B"),
        ("block_version_low", "B"),
    ),
    payload=False,
    statics={
        "IODReadRequestHeader": 0x0009,
        "IODReadResponseHeader": 0x8009,
        "InM0": 0x0020,
        "InM0FilterDataSubModul": 0x0030,
        "InM0FilterDataModul": 0x0031,
        "InM0FilterDataDevice": 0x0032,
    },
)


PNARBlockRequest = make_packet(
    "PNARBlockRequest",
    (
        ("block_header", "6s"),
        ("ar_type", "H"),
        ("ar_uuid", "16s"),
        ("session_key", "H"),
        ("cm_initiator_mac_address", "6s"),
        ("cm_initiator_object_uuid", "16s"),
        ("ar_properties", "I"),
        ("cm_initiator_activity_timeout_factor", "H"),
        ("initiator_udp_rtport", "H"),
        ("station_name_length", "H"),
    ),
    vlf="cm_initiator_station_name",
    vlf_size_field="station_name_length",
)


PNIODReleaseBlock = make_packet(
    "PNIODReleaseBlock",
    (
        ("block_header", "6s"),
        ("padding1", "H"),
        ("ar_uuid", "16s"),
        ("session_key", "H"),
        ("padding2", "H"),
        ("control_command", "H"),
        ("control_block_properties", "H"),
    ),
)


# =============================================================================
# I&M (Identification & Maintenance) Data
# =============================================================================

PNInM0 = make_packet(
    "PNInM0",
    (
        ("block_header", "6s"),
        ("vendor_id_high", "B"),
        ("vendor_id_low", "B"),
        ("order_id", ("20s", decode_bytes)),
        ("im_serial_number", ("16s", decode_bytes)),
        ("im_hardware_revision", "H"),
        ("sw_revision_prefix", "B"),
        ("im_sw_revision_functional_enhancement", "B"),
        ("im_sw_revision_bug_fix", "B"),
        ("im_sw_revision_internal_change", "B"),
        ("im_revision_counter", "H"),
        ("im_profile_id", "H"),
        ("im_profile_specific_type", "H"),
        ("im_version", "H"),
        ("im_supported", "H"),
    ),
    payload=False,
    statics={"IDX": 0xAFF0},
)

# Convenience property: combined 16-bit vendor ID (matches DCPDeviceDescription API)
PNInM0.vendor_id = property(  # type: ignore[attr-defined]
    lambda self: (self.vendor_id_high << 8) | self.vendor_id_low
)


PNInM1 = make_packet(
    "PNInM1",
    (
        ("block_header", "6s"),
        ("im_tag_function", ("32s", decode_bytes)),
        ("im_tag_location", ("22s", decode_bytes)),
    ),
    payload=False,
    statics={"IDX": 0xAFF1},
)


PNInM2 = make_packet(
    "PNInM2",
    (
        ("block_header", "6s"),
        ("im_date", ("16s", decode_bytes)),  # YYYY-MM-DD HH:MM format
    ),
    payload=False,
    statics={"IDX": 0xAFF2},
)


PNInM3 = make_packet(
    "PNInM3",
    (
        ("block_header", "6s"),
        ("im_descriptor", ("54s", decode_bytes)),  # General descriptor
    ),
    payload=False,
    statics={"IDX": 0xAFF3},
)


PNInM4 = make_packet(
    "PNInM4",
    (
        ("block_header", "6s"),
        ("im_signature", "54s"),  # PROFIsafe signature (binary)
    ),
    payload=False,
    statics={"IDX": 0xAFF4},
)


PNInM5 = make_packet(
    "PNInM5",
    (
        ("block_header", "6s"),
        ("im_annotation", ("64s", decode_bytes)),  # Annotation string
    ),
    payload=False,
    statics={"IDX": 0xAFF5},
)


# I&M6-I&M15 are reserved for future use per IEC 61158-6-10
# They are defined as generic blocks with raw data payload

PNInM6 = make_packet(
    "PNInM6",
    (("block_header", "6s"),),
    statics={"IDX": 0xAFF6},
)

PNInM7 = make_packet(
    "PNInM7",
    (("block_header", "6s"),),
    statics={"IDX": 0xAFF7},
)

PNInM8 = make_packet(
    "PNInM8",
    (("block_header", "6s"),),
    statics={"IDX": 0xAFF8},
)

PNInM9 = make_packet(
    "PNInM9",
    (("block_header", "6s"),),
    statics={"IDX": 0xAFF9},
)

PNInM10 = make_packet(
    "PNInM10",
    (("block_header", "6s"),),
    statics={"IDX": 0xAFFA},
)

PNInM11 = make_packet(
    "PNInM11",
    (("block_header", "6s"),),
    statics={"IDX": 0xAFFB},
)

PNInM12 = make_packet(
    "PNInM12",
    (("block_header", "6s"),),
    statics={"IDX": 0xAFFC},
)

PNInM13 = make_packet(
    "PNInM13",
    (("block_header", "6s"),),
    statics={"IDX": 0xAFFD},
)

PNInM14 = make_packet(
    "PNInM14",
    (("block_header", "6s"),),
    statics={"IDX": 0xAFFE},
)

PNInM15 = make_packet(
    "PNInM15",
    (("block_header", "6s"),),
    statics={"IDX": 0xAFFF},
)


# =============================================================================
# IOCR (IO Connection Relationship) Blocks
# =============================================================================

# IOCRAPIObject - describes slot/subslot in an IOCR (6 bytes per object)
IOCRAPIObject = make_packet(
    "IOCRAPIObject",
    (
        ("slot_number", "H"),
        ("subslot_number", "H"),
        ("frame_offset", "H"),
    ),
    payload=False,
)


# IOCRBlockRes (0x8102) - response to IOCRBlockReq
PNIOCRBlockRes = make_packet(
    "PNIOCRBlockRes",
    (
        ("block_header", "6s"),
        ("iocr_type", "H"),
        ("iocr_reference", "H"),
        ("frame_id", "H"),
    ),
    payload=False,
    statics={"BLOCK_TYPE": 0x8102},
)


# IOCRBlockReq fixed header (0x0102) - variable payload with IOCRAPI list
PNIOCRBlockReqHeader = make_packet(
    "PNIOCRBlockReqHeader",
    (
        ("block_header", "6s"),
        ("iocr_type", "H"),
        ("iocr_reference", "H"),
        ("lt", "H"),  # Ethertype (0x8892)
        ("iocr_properties", "I"),  # RT class in bits 0-3
        ("data_length", "H"),
        ("frame_id", "H"),
        ("send_clock_factor", "H"),
        ("reduction_ratio", "H"),
        ("phase", "H"),
        ("sequence", "H"),
        ("frame_send_offset", "I"),
        ("watchdog_factor", "H"),
        ("data_hold_factor", "H"),
        ("iocr_tag_header", "H"),
        ("iocr_multicast_mac", "6s"),
        ("number_of_apis", "H"),
    ),
    payload=False,
    statics={"BLOCK_TYPE": 0x0102},
)


# =============================================================================
# AlarmCR (Alarm Connection Relationship) Blocks
# =============================================================================

# AlarmCRBlockReq (0x0103) - 26 bytes total
PNAlarmCRBlockReq = make_packet(
    "PNAlarmCRBlockReq",
    (
        ("block_header", "6s"),
        ("alarm_cr_type", "H"),
        ("lt", "H"),  # Ethertype (0x8892 or 0x0800 for UDP)
        ("alarm_cr_properties", "I"),  # bit 0: priority, bit 1: transport
        ("rta_timeout_factor", "H"),
        ("rta_retries", "H"),
        ("local_alarm_reference", "H"),
        ("max_alarm_data_length", "H"),
        ("alarm_cr_tag_header_high", "H"),
        ("alarm_cr_tag_header_low", "H"),
    ),
    payload=False,
    statics={
        "BLOCK_TYPE": 0x0103,
        "DEFAULT_RTA_TIMEOUT_FACTOR": 1,
        "DEFAULT_RTA_RETRIES": 3,
        "DEFAULT_MAX_ALARM_DATA_LENGTH": 200,
        "DEFAULT_TAG_HEADER_HIGH": 0xC000,
        "DEFAULT_TAG_HEADER_LOW": 0xA000,
    },
)


# AlarmCRBlockRes (0x8103) - response
PNAlarmCRBlockRes = make_packet(
    "PNAlarmCRBlockRes",
    (
        ("block_header", "6s"),
        ("alarm_cr_type", "H"),
        ("local_alarm_reference", "H"),
        ("max_alarm_data_length", "H"),
    ),
    payload=False,
    statics={"BLOCK_TYPE": 0x8103},
)


# =============================================================================
# Alarm Notification PDUs
# =============================================================================

# AlarmNotificationPDU - base structure for alarm notifications
PNAlarmNotificationPDU = make_packet(
    "PNAlarmNotificationPDU",
    (
        ("block_header", "6s"),
        ("alarm_type", "H"),
        ("api", "I"),
        ("slot_number", "H"),
        ("subslot_number", "H"),
        ("module_ident_number", "I"),
        ("submodule_ident_number", "I"),
        ("alarm_specifier", "H"),
    ),
    statics={
        "BLOCK_ALARM_HIGH": 0x0001,
        "BLOCK_ALARM_LOW": 0x0002,
        "BLOCK_ALARM_ACK_HIGH": 0x8001,
        "BLOCK_ALARM_ACK_LOW": 0x8002,
    },
)


# AlarmAck PDU - alarm acknowledgment
PNAlarmAckPDU = make_packet(
    "PNAlarmAckPDU",
    (
        ("block_header", "6s"),
        ("alarm_type", "H"),
        ("api", "I"),
        ("slot_number", "H"),
        ("subslot_number", "H"),
        ("alarm_specifier", "H"),
        ("pnio_status", "I"),
    ),
    payload=False,
)


# RTA-PDU Header - Real-Time Acyclic PDU for Layer 2 alarm transport
PNRTAHeader = make_packet(
    "PNRTAHeader",
    (
        ("alarm_dst_endpoint", "H"),
        ("alarm_src_endpoint", "H"),
        ("pdu_type", "B"),  # bits: type(4) + version(4)
        ("add_flags", "B"),
        ("send_seq_num", "H"),
        ("ack_seq_num", "H"),
        ("var_part_len", "H"),
    ),
    statics={
        "RTA_TYPE_DATA": 0x01,
        "RTA_TYPE_NACK": 0x02,
        "RTA_TYPE_ACK": 0x03,
        "RTA_TYPE_ERR": 0x04,
        "VERSION_1": 0x01,
        "VERSION_2": 0x02,
    },
)


# =============================================================================
# ExpectedSubmodule Blocks (0x0104)
# =============================================================================

# ExpectedSubmoduleDataDescription - describes I/O data for a submodule
PNExpectedSubmoduleDataDescription = make_packet(
    "PNExpectedSubmoduleDataDescription",
    (
        ("data_description", "H"),  # 1=Input, 2=Output
        ("submodule_data_length", "H"),
        ("length_iocs", "B"),
        ("length_iops", "B"),
    ),
    payload=False,
)


# =============================================================================
# IOD Write/Read Request Blocks
# =============================================================================

# IODWriteReq - single write request block
PNIODWriteReq = make_packet(
    "PNIODWriteReq",
    (
        ("block_header", "6s"),
        ("seq_num", "H"),
        ("ar_uuid", "16s"),
        ("api", "I"),
        ("slot", "H"),
        ("subslot", "H"),
        ("padding", "H"),
        ("index", "H"),
        ("record_data_length", "I"),
        ("rw_padding", "24s"),
    ),
    statics={"BLOCK_TYPE": 0x0008},
)


# IODWriteRes - single write response block
PNIODWriteRes = make_packet(
    "PNIODWriteRes",
    (
        ("block_header", "6s"),
        ("seq_num", "H"),
        ("ar_uuid", "16s"),
        ("api", "I"),
        ("slot", "H"),
        ("subslot", "H"),
        ("padding", "H"),
        ("index", "H"),
        ("record_data_length", "I"),
        ("additional_value1", "H"),
        ("additional_value2", "H"),
        ("status", "I"),
        ("rw_padding", "16s"),
    ),
    statics={"BLOCK_TYPE": 0x8008},
)
