"""
PROFINET Alarm handling.

Provides alarm item dataclasses and parsing functions for:
- AlarmNotification parsing
- Alarm item types (Diagnosis, Maintenance, PE, RS, etc.)
- USI (User Structure Identifier) dispatch

Per IEC 61158-6-10.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

import construct as cs

from . import indices

# Construct definitions for alarm parsing
_DiagnosisBaseStruct = cs.Struct(
    "channel_number" / cs.Int16ub,
    "channel_properties" / cs.Int16ub,
    "error_type" / cs.Int16ub,
)

_ExtDiagnosisStruct = cs.Struct(
    "ext_error_type" / cs.Int16ub,
    "ext_add_value" / cs.Int32ub,
)

_BlockHeaderStruct = cs.Struct(
    "block_type" / cs.Int16ub,
    "block_length" / cs.Int16ub,
    "ver_high" / cs.Int8ub,
    "ver_low" / cs.Int8ub,
)

_AlarmNotificationBodyStruct = cs.Struct(
    "alarm_type" / cs.Int16ub,
    "api" / cs.Int32ub,
    "slot_number" / cs.Int16ub,
    "subslot_number" / cs.Int16ub,
    "module_ident" / cs.Int32ub,
    "submodule_ident" / cs.Int32ub,
    "alarm_specifier" / cs.Int16ub,
)

_PralStruct = cs.Struct(
    "channel_num" / cs.Int16ub,
    "channel_props" / cs.Int16ub,
    "reason" / cs.Int16ub,
    "ext_reason" / cs.Int16ub,
)

# Single-field Structs (replace standalone cs.Int16ub/Int32ub.parse() calls)
_UInt16ubStruct = cs.Struct("value" / cs.Int16ub)
_UInt32ubStruct = cs.Struct("value" / cs.Int32ub)

_UploadRetrievalBodyStruct = cs.Struct(
    "ur_index" / cs.Int32ub,
    "ur_length" / cs.Int32ub,
)

# =============================================================================
# Alarm Item Base Classes
# =============================================================================


@dataclass
class AlarmItem:
    """Base class for alarm payload items.

    All alarm items start with UserStructureIdentifier (USI).
    USI determines the item type and parsing format.
    """

    user_structure_id: int = 0
    raw_data: bytes = b""

    @property
    def usi_name(self) -> str:
        """Human-readable USI name."""
        return indices.get_usi_name(self.user_structure_id)


# =============================================================================
# Specific Alarm Item Types
# =============================================================================


@dataclass
class DiagnosisItem(AlarmItem):
    """Diagnosis alarm item (USI 0x8000, 0x8002, 0x8003).

    Format depends on USI:
    - 0x8000: ChannelNumber(2) + ChannelProperties(2) + ChannelErrorType(2)
    - 0x8002: + ExtChannelErrorType(2) + ExtChannelAddValue(4)
    - 0x8003: + QualifiedChannelQualifier(4)
    """

    channel_number: int = 0
    channel_properties: int = 0
    channel_error_type: int = 0
    ext_channel_error_type: int = 0
    ext_channel_add_value: int = 0
    qualified_channel_qualifier: int = 0

    @property
    def channel_number_value(self) -> int:
        """Get actual channel number (bits 0-14)."""
        return self.channel_number & 0x7FFF

    @property
    def is_accumulative(self) -> bool:
        """Bit 15: accumulative (multiple errors on channel)."""
        return bool(self.channel_number & 0x8000)

    @property
    def channel_type(self) -> int:
        """Get channel type from properties (bits 0-7)."""
        return self.channel_properties & 0xFF

    @property
    def is_extended(self) -> bool:
        """True if this is an extended diagnosis (USI 0x8002 or 0x8003)."""
        return self.user_structure_id in (
            indices.USI_EXT_CHANNEL_DIAGNOSIS,
            indices.USI_QUALIFIED_CHANNEL_DIAGNOSIS,
        )

    @property
    def is_qualified(self) -> bool:
        """True if this is a qualified diagnosis (USI 0x8003)."""
        return self.user_structure_id == indices.USI_QUALIFIED_CHANNEL_DIAGNOSIS


@dataclass
class MaintenanceItem(AlarmItem):
    """Maintenance alarm item (USI 0x8100).

    Format: BlockHeader(6) + Padding(2) + MaintenanceStatus(4)
    """

    user_structure_id: int = indices.USI_MAINTENANCE
    block_type: int = 0
    block_length: int = 0
    block_version: int = 0
    maintenance_status: int = 0

    @property
    def maintenance_required(self) -> bool:
        """Bit 0: Maintenance required."""
        return bool(self.maintenance_status & 0x01)

    @property
    def maintenance_demanded(self) -> bool:
        """Bit 1: Maintenance demanded."""
        return bool(self.maintenance_status & 0x02)


@dataclass
class UploadRetrievalItem(AlarmItem):
    """Upload/Retrieval alarm item (USI 0x8200, 0x8201).

    Format: BlockHeader(6) + Padding(2) + URRecordIndex(4) + URRecordLength(4)
    """

    block_type: int = 0
    block_length: int = 0
    block_version: int = 0
    ur_record_index: int = 0
    ur_record_length: int = 0

    @property
    def is_upload(self) -> bool:
        """True if this is an upload request."""
        return self.user_structure_id == indices.USI_UPLOAD

    @property
    def is_retrieval(self) -> bool:
        """True if this is a retrieval request."""
        return self.user_structure_id == indices.USI_IPARAMETER


@dataclass
class iParameterItem(AlarmItem):
    """iParameter alarm item (USI 0x8201).

    Format:
      BlockHeader(6) + Padding(2) +
      iPar_Req_Header(4) + Max_Segm_Size(4) +
      Transfer_Index(4) + Total_iPar_Size(4)
    """

    user_structure_id: int = indices.USI_IPARAMETER
    block_type: int = 0
    block_length: int = 0
    block_version: int = 0
    ipar_req_header: int = 0
    max_segment_size: int = 0
    transfer_index: int = 0
    total_ipar_size: int = 0


@dataclass
class PE_AlarmItem(AlarmItem):
    """PROFIenergy alarm item (USI 0x8310).

    Format: BlockHeader(6) + PE_OperationalMode(1)
    """

    user_structure_id: int = indices.USI_PE_ALARM
    block_type: int = 0
    block_length: int = 0
    block_version: int = 0
    pe_operational_mode: int = 0

    @property
    def mode_name(self) -> str:
        """Human-readable mode name."""
        return indices.get_pe_mode_name(self.pe_operational_mode)


@dataclass
class RS_AlarmItem(AlarmItem):
    """Reporting System alarm item (USI 0x8300-0x8302).

    Format: RS_AlarmInfo(2)
    """

    rs_alarm_info: int = 0

    @property
    def rs_specifier(self) -> int:
        """RS Specifier from AlarmInfo (bits 0-10)."""
        return self.rs_alarm_info & 0x07FF

    @property
    def rs_sequence_number(self) -> int:
        """Sequence number (same as specifier for these items)."""
        return self.rs_specifier


@dataclass
class PRAL_AlarmItem(AlarmItem):
    """Pull Request Alarm item (USI 0x8320).

    Format:
      ChannelNumber(2) + PRAL_ChannelProperties(2) +
      PRAL_Reason(2) + PRAL_ExtReason(2) +
      PRAL_ReasonAddValue(variable)
    """

    user_structure_id: int = indices.USI_PRAL_ALARM
    channel_number: int = 0
    pral_channel_properties: int = 0
    pral_reason: int = 0
    pral_ext_reason: int = 0
    pral_reason_add_value: bytes = b""


# =============================================================================
# Alarm Notification
# =============================================================================


@dataclass
class AlarmNotification:
    """Complete parsed alarm notification.

    Combines the PDU header with parsed alarm items.
    """

    # From block header
    block_type: int = 0
    block_version: Tuple[int, int] = (1, 0)

    # From PDU body
    alarm_type: int = 0
    api: int = 0
    slot_number: int = 0
    subslot_number: int = 0
    module_ident_number: int = 0
    submodule_ident_number: int = 0

    # AlarmSpecifier bits
    alarm_sequence_number: int = 0
    channel_diagnosis: bool = False
    manufacturer_specific: bool = False
    submodule_diagnosis_state: bool = False
    ar_diagnosis_state: bool = False

    # Parsed alarm payload items
    items: List[AlarmItem] = field(default_factory=list)

    # Raw data for debugging
    raw_payload: bytes = b""

    @property
    def is_high_priority(self) -> bool:
        """True if this is a high-priority alarm."""
        return self.block_type == indices.BLOCK_ALARM_NOTIFICATION_HIGH

    @property
    def is_low_priority(self) -> bool:
        """True if this is a low-priority alarm."""
        return self.block_type == indices.BLOCK_ALARM_NOTIFICATION_LOW

    @property
    def alarm_type_name(self) -> str:
        """Human-readable alarm type."""
        return indices.get_alarm_type_name(self.alarm_type)

    @property
    def location(self) -> str:
        """Location string (API:Slot:Subslot)."""
        return f"{self.api}:{self.slot_number}:0x{self.subslot_number:04X}"


# =============================================================================
# Parsing Functions
# =============================================================================


def parse_alarm_item(data: bytes, offset: int = 0) -> Tuple[AlarmItem, int]:
    """Parse a single alarm item from data.

    Args:
        data: Raw bytes containing alarm items
        offset: Starting offset

    Returns:
        Tuple of (parsed AlarmItem, new offset after item)

    Raises:
        ValueError: If data is truncated or invalid
    """
    if len(data) < offset + 2:
        raise ValueError("Insufficient data for USI")

    usi = _UInt16ubStruct.parse(data[offset : offset + 2]).value
    offset += 2

    # Dispatch to specific parser based on USI
    if usi in (
        indices.USI_CHANNEL_DIAGNOSIS,
        indices.USI_EXT_CHANNEL_DIAGNOSIS,
        indices.USI_QUALIFIED_CHANNEL_DIAGNOSIS,
    ):
        return _parse_diagnosis_item(data, offset, usi)
    elif usi == indices.USI_MAINTENANCE:
        return _parse_maintenance_item(data, offset)
    elif usi in (indices.USI_UPLOAD, indices.USI_IPARAMETER):
        return _parse_upload_retrieval_item(data, offset, usi)
    elif usi in (
        indices.USI_RS_ALARM_LOW,
        indices.USI_RS_ALARM_HIGH,
        indices.USI_RS_ALARM_SUBMODULE,
    ):
        return _parse_rs_alarm_item(data, offset, usi)
    elif usi == indices.USI_PE_ALARM:
        return _parse_pe_alarm_item(data, offset)
    elif usi == indices.USI_PRAL_ALARM:
        return _parse_pral_alarm_item(data, offset)
    else:
        # Unknown/manufacturer-specific: return generic item with remaining data
        return AlarmItem(user_structure_id=usi, raw_data=data[offset:]), len(data)


def _parse_diagnosis_item(data: bytes, offset: int, usi: int) -> Tuple[DiagnosisItem, int]:
    """Parse DiagnosisItem (USI 0x8000, 0x8002, 0x8003)."""
    # Base fields: ChannelNumber(2) + ChannelProperties(2) + ChannelErrorType(2)
    if len(data) < offset + 6:
        raise ValueError("Truncated DiagnosisItem")

    parsed = _DiagnosisBaseStruct.parse(data[offset : offset + 6])
    channel_number = parsed.channel_number
    channel_props = parsed.channel_properties
    error_type = parsed.error_type
    offset += 6

    item = DiagnosisItem(
        user_structure_id=usi,
        channel_number=channel_number,
        channel_properties=channel_props,
        channel_error_type=error_type,
    )

    # Extended diagnosis (USI 0x8002, 0x8003)
    if usi in (indices.USI_EXT_CHANNEL_DIAGNOSIS, indices.USI_QUALIFIED_CHANNEL_DIAGNOSIS):
        if len(data) < offset + 6:
            raise ValueError("Truncated ExtChannelDiagnosis")
        parsed_ext = _ExtDiagnosisStruct.parse(data[offset : offset + 6])
        ext_error_type = parsed_ext.ext_error_type
        ext_add_value = parsed_ext.ext_add_value
        item.ext_channel_error_type = ext_error_type
        item.ext_channel_add_value = ext_add_value
        offset += 6

    # Qualified diagnosis (USI 0x8003)
    if usi == indices.USI_QUALIFIED_CHANNEL_DIAGNOSIS:
        if len(data) < offset + 4:
            raise ValueError("Truncated QualifiedChannelDiagnosis")
        qualifier = _UInt32ubStruct.parse(data[offset : offset + 4]).value
        item.qualified_channel_qualifier = qualifier
        offset += 4

    return item, offset


def _parse_maintenance_item(data: bytes, offset: int) -> Tuple[MaintenanceItem, int]:
    """Parse MaintenanceItem (USI 0x8100)."""
    # BlockHeader(6) + Padding(2) + MaintenanceStatus(4) = 12 bytes
    if len(data) < offset + 12:
        raise ValueError("Truncated MaintenanceItem")

    hdr = _BlockHeaderStruct.parse(data[offset : offset + 6])
    offset += 6

    # Skip 2-byte padding
    offset += 2

    maint_status = _UInt32ubStruct.parse(data[offset : offset + 4]).value
    offset += 4

    return MaintenanceItem(
        user_structure_id=indices.USI_MAINTENANCE,
        block_type=hdr.block_type,
        block_length=hdr.block_length,
        block_version=(hdr.ver_high << 8) | hdr.ver_low,
        maintenance_status=maint_status,
    ), offset


def _parse_upload_retrieval_item(
    data: bytes, offset: int, usi: int
) -> Tuple[UploadRetrievalItem, int]:
    """Parse UploadRetrievalItem (USI 0x8200, 0x8201)."""
    # BlockHeader(6) + Padding(2) + URRecordIndex(4) + URRecordLength(4) = 16 bytes
    if len(data) < offset + 16:
        raise ValueError("Truncated UploadRetrievalItem")

    hdr = _BlockHeaderStruct.parse(data[offset : offset + 6])
    offset += 6
    offset += 2  # Padding

    body = _UploadRetrievalBodyStruct.parse(data[offset : offset + 8])
    offset += 8

    return UploadRetrievalItem(
        user_structure_id=usi,
        block_type=hdr.block_type,
        block_length=hdr.block_length,
        block_version=(hdr.ver_high << 8) | hdr.ver_low,
        ur_record_index=body.ur_index,
        ur_record_length=body.ur_length,
    ), offset


def _parse_pe_alarm_item(data: bytes, offset: int) -> Tuple[PE_AlarmItem, int]:
    """Parse PE_AlarmItem (USI 0x8310)."""
    # BlockHeader(6) + PE_OperationalMode(1) = 7 bytes
    if len(data) < offset + 7:
        raise ValueError("Truncated PE_AlarmItem")

    hdr = _BlockHeaderStruct.parse(data[offset : offset + 6])
    offset += 6

    pe_mode = data[offset]
    offset += 1

    return PE_AlarmItem(
        user_structure_id=indices.USI_PE_ALARM,
        block_type=hdr.block_type,
        block_length=hdr.block_length,
        block_version=(hdr.ver_high << 8) | hdr.ver_low,
        pe_operational_mode=pe_mode,
    ), offset


def _parse_rs_alarm_item(data: bytes, offset: int, usi: int) -> Tuple[RS_AlarmItem, int]:
    """Parse RS_AlarmItem (USI 0x8300-0x8302)."""
    # RS_AlarmInfo(2) = 2 bytes
    if len(data) < offset + 2:
        raise ValueError("Truncated RS_AlarmItem")

    rs_info = _UInt16ubStruct.parse(data[offset : offset + 2]).value
    offset += 2

    return RS_AlarmItem(
        user_structure_id=usi,
        rs_alarm_info=rs_info,
    ), offset


def _parse_pral_alarm_item(data: bytes, offset: int) -> Tuple[PRAL_AlarmItem, int]:
    """Parse PRAL_AlarmItem (USI 0x8320)."""
    # ChannelNumber(2) + PRAL_ChannelProperties(2) + PRAL_Reason(2) +
    # PRAL_ExtReason(2) + PRAL_ReasonAddValue(variable) = 8+ bytes
    if len(data) < offset + 8:
        raise ValueError("Truncated PRAL_AlarmItem")

    pral = _PralStruct.parse(data[offset : offset + 8])
    channel_num = pral.channel_num
    channel_props = pral.channel_props
    reason = pral.reason
    ext_reason = pral.ext_reason
    offset += 8

    # Remaining bytes are PRAL_ReasonAddValue
    add_value = data[offset:]

    return PRAL_AlarmItem(
        user_structure_id=indices.USI_PRAL_ALARM,
        channel_number=channel_num,
        pral_channel_properties=channel_props,
        pral_reason=reason,
        pral_ext_reason=ext_reason,
        pral_reason_add_value=add_value,
    ), len(data)


def parse_alarm_notification(data: bytes) -> AlarmNotification:
    """Parse complete AlarmNotification PDU.

    Args:
        data: Raw bytes of AlarmNotification block

    Returns:
        Parsed AlarmNotification with items

    Raises:
        ValueError: If data is truncated or invalid
    """
    if len(data) < 28:  # Minimum: BlockHeader(6) + Body(22)
        raise ValueError("AlarmNotification too short")

    offset = 0

    # Parse block header
    hdr = _BlockHeaderStruct.parse(data[offset : offset + 6])
    block_type = hdr.block_type
    ver_high = hdr.ver_high
    ver_low = hdr.ver_low
    offset += 6

    # Parse PDU body
    body = _AlarmNotificationBodyStruct.parse(data[offset : offset + 22])
    alarm_type = body.alarm_type
    api = body.api
    slot_number = body.slot_number
    subslot_number = body.subslot_number
    module_ident = body.module_ident
    submodule_ident = body.submodule_ident
    alarm_specifier = body.alarm_specifier
    offset += 22

    # Decode alarm specifier bits
    seq_num = alarm_specifier & 0x07FF  # Bits 0-10
    channel_diag = bool(alarm_specifier & 0x0800)  # Bit 11
    mfr_specific = bool(alarm_specifier & 0x1000)  # Bit 12
    submod_diag = bool(alarm_specifier & 0x2000)  # Bit 13
    ar_diag = bool(alarm_specifier & 0x4000)  # Bit 14

    notification = AlarmNotification(
        block_type=block_type,
        block_version=(ver_high, ver_low),
        alarm_type=alarm_type,
        api=api,
        slot_number=slot_number,
        subslot_number=subslot_number,
        module_ident_number=module_ident,
        submodule_ident_number=submodule_ident,
        alarm_sequence_number=seq_num,
        channel_diagnosis=channel_diag,
        manufacturer_specific=mfr_specific,
        submodule_diagnosis_state=submod_diag,
        ar_diagnosis_state=ar_diag,
        raw_payload=data[offset:],
    )

    # Parse alarm payload items
    payload_data = data[offset:]
    item_offset = 0

    while item_offset < len(payload_data):
        try:
            item, item_offset = parse_alarm_item(payload_data, item_offset)
            notification.items.append(item)
        except ValueError:
            # Stop parsing on error, keep what we have
            break

    return notification
