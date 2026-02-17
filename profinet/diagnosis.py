"""
PROFINET Diagnosis parsing and decoding.

Provides comprehensive diagnosis data parsing including:
- ChannelDiagnosis (USI 0x8000)
- ExtChannelDiagnosis (USI 0x8002)
- QualifiedChannelDiagnosis (USI 0x8003)
- Error type decoding with human-readable names

References:
- IEC 61158 PROFINET IO specification
- Wireshark PROFINET dissector
- CODESYS PROFINET documentation
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List

import construct as cs

logger = logging.getLogger(__name__)

# =============================================================================
# Construct Struct Definitions for Diagnosis Parsing
# =============================================================================

# Block header for diagnosis blocks (BlockType + BlockLength)
DiagBlockHeaderStruct = cs.Struct(
    "block_type" / cs.Int16ub,
    "block_length" / cs.Int16ub,
)

# API / Slot / Subslot location header
ApiSlotSubslotStruct = cs.Struct(
    "api" / cs.Int32ub,
    "slot" / cs.Int16ub,
    "subslot" / cs.Int16ub,
)

# Common channel header: ChannelNumber + ChannelProperties + USI
ChannelHeaderStruct = cs.Struct(
    "channel_number" / cs.Int16ub,
    "channel_properties" / cs.Int16ub,
    "usi" / cs.Int16ub,
)

# ChannelDiagnosis body (USI 0x8000): just ChannelErrorType
ChannelDiagBodyStruct = cs.Struct(
    "error_type" / cs.Int16ub,
)

# ExtChannelDiagnosis body (USI 0x8002): ChannelErrorType + ExtChannelErrorType + ExtChannelAddValue
ExtChannelDiagBodyStruct = cs.Struct(
    "error_type" / cs.Int16ub,
    "ext_error_type" / cs.Int16ub,
    "ext_add_value" / cs.Int32ub,
)

# QualifiedChannelDiagnosis body (USI 0x8003): same as Ext + QualifiedChannelQualifier
QualifiedChannelDiagBodyStruct = cs.Struct(
    "error_type" / cs.Int16ub,
    "ext_error_type" / cs.Int16ub,
    "ext_add_value" / cs.Int32ub,
    "qualifier" / cs.Int32ub,
)

# Simple diagnosis entry: ChannelNumber + ChannelProperties + ChannelErrorType
SimpleDiagEntryStruct = cs.Struct(
    "channel_number" / cs.Int16ub,
    "channel_properties" / cs.Int16ub,
    "error_type" / cs.Int16ub,
)


# =============================================================================
# User Structure Identifiers
# =============================================================================


class UserStructureIdentifier(IntEnum):
    """USI values define the diagnosis type."""

    CHANNEL_DIAGNOSIS = 0x8000
    MULTIPLE = 0x8001
    EXT_CHANNEL_DIAGNOSIS = 0x8002
    QUALIFIED_CHANNEL_DIAGNOSIS = 0x8003
    MAINTENANCE = 0x8100
    # 0x0000-0x7FFF: Manufacturer-specific
    # 0x8004-0x80FF: Reserved
    # 0x9000-0x9FFF: Reserved for profiles
    # 0xA000-0xFFFF: Reserved


# =============================================================================
# Channel Properties Bit Fields
# =============================================================================


class ChannelType(IntEnum):
    """Channel type from ChannelProperties bits 0-1."""

    RESERVED = 0
    SPECIFIC = 1  # Specific channel
    ALL = 2  # All channels (submodule)
    SUBMODULE = 3  # Whole submodule


class ChannelDirection(IntEnum):
    """Channel direction from ChannelProperties bits 11-12."""

    MANUFACTURER = 0  # Manufacturer-specific
    INPUT = 1
    OUTPUT = 2
    BIDIRECTIONAL = 3


class ChannelAccumulative(IntEnum):
    """Accumulative info from ChannelProperties bits 2-4."""

    NO = 0
    MAIN_FAULT = 1  # Main diagnosis (main fault)
    ADDITIONAL_FAULT = 2  # Additional diagnosis
    # 3-7: Reserved


class ChannelSpecifier(IntEnum):
    """Specifier from ChannelProperties bits 8-10."""

    ALL_DISAPPEARS = 0  # All diagnosis of submodule disappears
    APPEARS = 1  # Diagnosis appears
    DISAPPEARS = 2  # Diagnosis disappears
    DISAPPEARS_OTHER = 3  # Diagnosis disappears, others remain
    # 4-7: Reserved


# =============================================================================
# Channel Error Types (Standard PROFINET)
# =============================================================================

CHANNEL_ERROR_TYPES: Dict[int, str] = {
    # Basic errors (0x0001 - 0x001F)
    0x0000: "Reserved",
    0x0001: "Short circuit",
    0x0002: "Undervoltage",
    0x0003: "Overvoltage",
    0x0004: "Overload",
    0x0005: "Overtemperature",
    0x0006: "Line break",
    0x0007: "Upper limit value exceeded",
    0x0008: "Lower limit value exceeded",
    0x0009: "Error",
    0x000A: "Simulation active",
    0x000B: "Reserved (0x000B)",
    0x000C: "Reserved (0x000C)",
    0x000D: "Reserved (0x000D)",
    0x000E: "Reserved (0x000E)",
    0x000F: "Parameter missing",
    0x0010: "Parameterization fault",
    0x0011: "Power supply fault",
    0x0012: "Fuse blown / open",
    0x0013: "Communication fault",
    0x0014: "Ground fault",
    0x0015: "Reference point lost",
    0x0016: "Process event lost",
    0x0017: "Threshold warning",
    0x0018: "Output disabled",
    0x0019: "Functional safety event",
    0x001A: "External fault",
    0x001B: "Sensor has incorrect configuration",
    0x001C: "Reserved (0x001C)",
    0x001D: "Reserved (0x001D)",
    0x001E: "Reserved (0x001E)",
    0x001F: "Temporary fault",
    # 0x0020 - 0x00FF: Reserved
    # 0x0100 - 0x7FFF: Manufacturer-specific
    # Network/system level errors (0x8000+)
    0x8000: "Data transmission impossible",
    0x8001: "Remote mismatch",
    0x8002: "Media redundancy mismatch",
    0x8003: "Sync mismatch",
    0x8004: "Isochronous mode mismatch",
    0x8005: "Multicast CR mismatch",
    0x8006: "Reserved (0x8006)",
    0x8007: "Fiber optic mismatch",
    0x8008: "Network component function mismatch",
    0x8009: "Time mismatch",
    0x800A: "Dynamic frame packing function mismatch",
    0x800B: "Media redundancy with planned duplication mismatch",
    0x800C: "System redundancy mismatch",
    0x800D: "Multiple interface mismatch",
    # 0x800E - 0x8FFF: Reserved
    # 0x9000 - 0x9FFF: Reserved for profiles
    # IO-Link (0x9500+)
    0x9500: "IO-Link device event",
    0x9501: "IO-Link device event (MSB cleared)",
    0x9502: "IO-Link port event",
}


# =============================================================================
# Extended Channel Error Types (per ChannelErrorType)
# =============================================================================

# For ChannelErrorType 0x0000 - 0x7FFF (general)
EXT_CHANNEL_ERROR_TYPES_GENERAL: Dict[int, str] = {
    0x0000: "Reserved",
    0x8000: "Accumulative info",
    # 0x0001 - 0x7FFF: Manufacturer-specific
    # 0x8001 - 0x8FFF: Reserved
    # 0x9000 - 0x9FFF: Reserved for profiles
}

# For ChannelErrorType 0x8000 (Data transmission impossible)
EXT_CHANNEL_ERROR_TYPES_0x8000: Dict[int, str] = {
    0x0000: "Reserved",
    0x8000: "Link state mismatch - Loss of link",
    0x8001: "MAUType mismatch",
    0x8002: "Line delay mismatch",
    # 0x8003 - 0x8FFF: Reserved
    # 0x9000 - 0x9FFF: Reserved for profiles
}

# For ChannelErrorType 0x8001 (Remote mismatch)
EXT_CHANNEL_ERROR_TYPES_0x8001: Dict[int, str] = {
    0x0000: "Reserved",
    0x8000: "Peer name of station mismatch",
    0x8001: "Peer name of port mismatch",
    0x8002: "Peer RT_CLASS_3 mismatch",
    0x8003: "Peer MAUType mismatch",
    0x8004: "Peer MRP domain mismatch",
    0x8005: "No peer detected",
    0x8006: "Peer line delay mismatch",
    0x8007: "Peer PTCP mismatch",
    0x8008: "Peer Preamble length mismatch",
    0x8009: "Peer Fragmentation mismatch",
    # 0x800A - 0x8FFF: Reserved
}

# For ChannelErrorType 0x8002 (Media redundancy mismatch)
EXT_CHANNEL_ERROR_TYPES_0x8002: Dict[int, str] = {
    0x0000: "Reserved",
    0x8000: "Manager role fail",
    0x8001: "MRP-Loss of redundancy",
    0x8002: "Reserved (0x8002)",
    0x8003: "MRP ring open",
    0x8004: "MRP multiple manager",
    # 0x8005 - 0x8FFF: Reserved
}

# For ChannelErrorType 0x8003 (Sync mismatch)
EXT_CHANNEL_ERROR_TYPES_0x8003: Dict[int, str] = {
    0x0000: "Reserved",
    0x8000: "No sync message received",
    0x8001: "Jitter out of boundary",
    0x8002: "Sync message send failure",
    0x8003: "PTCP timeout",
    # 0x8004 - 0x8FFF: Reserved
}

# For ChannelErrorType 0x8007 (Fiber optic mismatch)
EXT_CHANNEL_ERROR_TYPES_0x8007: Dict[int, str] = {
    0x0000: "Reserved",
    0x8000: "Power budget exceeded",
    # 0x8001 - 0x8FFF: Reserved
}

# For ChannelErrorType 0x8008 (Network component function mismatch)
EXT_CHANNEL_ERROR_TYPES_0x8008: Dict[int, str] = {
    0x0000: "Reserved",
    0x8000: "Frame dropped - no resource",
    0x8001: "Frame dropped - wrong destination address",
    0x8002: "Frame dropped - no gateway",
    # 0x8003 - 0x8FFF: Reserved
}

# For ChannelErrorType 0x8009 (Time mismatch)
EXT_CHANNEL_ERROR_TYPES_0x8009: Dict[int, str] = {
    0x0000: "Reserved",
    0x8000: "No master detected",
    0x8001: "Drift exceeded",
    0x8002: "Time sync failure",
    # 0x8003 - 0x8FFF: Reserved
}

# For ChannelErrorType 0x800B (Media redundancy with planned duplication)
EXT_CHANNEL_ERROR_TYPES_0x800B: Dict[int, str] = {
    0x0000: "Reserved",
    0x8000: "MRPD loss of redundancy",
    # 0x8001 - 0x8FFF: Reserved
}

# Map ChannelErrorType to its ExtChannelErrorType lookup table
EXT_CHANNEL_ERROR_TYPES_MAP: Dict[int, Dict[int, str]] = {
    0x8000: EXT_CHANNEL_ERROR_TYPES_0x8000,
    0x8001: EXT_CHANNEL_ERROR_TYPES_0x8001,
    0x8002: EXT_CHANNEL_ERROR_TYPES_0x8002,
    0x8003: EXT_CHANNEL_ERROR_TYPES_0x8003,
    0x8007: EXT_CHANNEL_ERROR_TYPES_0x8007,
    0x8008: EXT_CHANNEL_ERROR_TYPES_0x8008,
    0x8009: EXT_CHANNEL_ERROR_TYPES_0x8009,
    0x800B: EXT_CHANNEL_ERROR_TYPES_0x800B,
}


# =============================================================================
# Diagnosis Data Classes
# =============================================================================


@dataclass
class ChannelProperties:
    """Parsed ChannelProperties bit field (16 bits)."""

    raw: int = 0
    channel_type: ChannelType = ChannelType.RESERVED
    accumulative: ChannelAccumulative = ChannelAccumulative.NO
    maintenance_required: bool = False
    maintenance_demanded: bool = False
    specifier: ChannelSpecifier = ChannelSpecifier.ALL_DISAPPEARS
    direction: ChannelDirection = ChannelDirection.MANUFACTURER

    @classmethod
    def from_uint16(cls, value: int) -> ChannelProperties:
        """Parse ChannelProperties from 16-bit value."""
        # Handle invalid enum values gracefully
        try:
            channel_type = ChannelType(value & 0x03)
        except ValueError:
            channel_type = ChannelType.RESERVED

        try:
            accumulative = ChannelAccumulative((value >> 2) & 0x07)
        except ValueError:
            accumulative = ChannelAccumulative.NO

        try:
            specifier = ChannelSpecifier((value >> 8) & 0x07)
        except ValueError:
            specifier = ChannelSpecifier.ALL_DISAPPEARS

        try:
            direction = ChannelDirection((value >> 11) & 0x03)
        except ValueError:
            direction = ChannelDirection.MANUFACTURER

        return cls(
            raw=value,
            channel_type=channel_type,
            accumulative=accumulative,
            maintenance_required=bool((value >> 5) & 0x01),
            maintenance_demanded=bool((value >> 6) & 0x01),
            # Bit 7 reserved
            specifier=specifier,
            direction=direction,
            # Bits 13-15 reserved
        )


@dataclass
class ChannelDiagnosis:
    """Channel diagnosis entry (USI 0x8000).

    Structure: ChannelNumber(2) + ChannelProperties(2) + ChannelErrorType(2)
    """

    api: int = 0
    slot: int = 0
    subslot: int = 0
    channel_number: int = 0
    channel_properties: ChannelProperties = field(default_factory=ChannelProperties)
    error_type: int = 0
    error_type_name: str = ""

    @property
    def is_submodule_level(self) -> bool:
        """True if this diagnosis applies to whole submodule (channel 0x8000)."""
        return self.channel_number == 0x8000


@dataclass
class ExtChannelDiagnosis(ChannelDiagnosis):
    """Extended channel diagnosis entry (USI 0x8002).

    Structure: ChannelNumber(2) + ChannelProperties(2) + ChannelErrorType(2)
               + ExtChannelErrorType(2) + ExtChannelAddValue(4)
    """

    ext_error_type: int = 0
    ext_error_type_name: str = ""
    ext_add_value: int = 0


@dataclass
class QualifiedChannelDiagnosis(ExtChannelDiagnosis):
    """Qualified channel diagnosis entry (USI 0x8003).

    Structure: Same as ExtChannelDiagnosis + QualifiedChannelQualifier(4)
    """

    qualifier: int = 0


@dataclass
class DiagnosisData:
    """Complete diagnosis data from a device."""

    api: int = 0
    slot: int = 0
    subslot: int = 0
    entries: List[ChannelDiagnosis] = field(default_factory=list)
    raw_data: bytes = b""

    @property
    def has_errors(self) -> bool:
        """True if any diagnosis entries exist."""
        return len(self.entries) > 0

    @property
    def has_maintenance_required(self) -> bool:
        """True if any entry has maintenance_required flag."""
        return any(e.channel_properties.maintenance_required for e in self.entries)

    @property
    def has_maintenance_demanded(self) -> bool:
        """True if any entry has maintenance_demanded flag."""
        return any(e.channel_properties.maintenance_demanded for e in self.entries)

    def get_by_channel(self, channel: int) -> List[ChannelDiagnosis]:
        """Get all entries for a specific channel."""
        return [e for e in self.entries if e.channel_number == channel]


# =============================================================================
# Decoding Functions
# =============================================================================


def decode_channel_error_type(error_type: int) -> str:
    """Decode ChannelErrorType to human-readable string."""
    if error_type in CHANNEL_ERROR_TYPES:
        return CHANNEL_ERROR_TYPES[error_type]
    elif 0x0020 <= error_type <= 0x00FF:
        return f"Reserved (0x{error_type:04X})"
    elif 0x0100 <= error_type <= 0x7FFF:
        return f"Manufacturer-specific (0x{error_type:04X})"
    elif 0x800E <= error_type <= 0x8FFF:
        return f"Reserved (0x{error_type:04X})"
    elif 0x9000 <= error_type <= 0x9FFF:
        return f"Profile-specific (0x{error_type:04X})"
    elif 0xA000 <= error_type <= 0xFFFF:
        return f"Reserved (0x{error_type:04X})"
    else:
        return f"Unknown (0x{error_type:04X})"


def decode_ext_channel_error_type(channel_error_type: int, ext_error_type: int) -> str:
    """Decode ExtChannelErrorType based on ChannelErrorType context."""
    # Get the lookup table for this ChannelErrorType
    lookup = EXT_CHANNEL_ERROR_TYPES_MAP.get(channel_error_type, EXT_CHANNEL_ERROR_TYPES_GENERAL)

    if ext_error_type in lookup:
        return lookup[ext_error_type]
    elif ext_error_type == 0x8000:
        return "Accumulative info"
    elif 0x0001 <= ext_error_type <= 0x7FFF:
        return f"Manufacturer-specific (0x{ext_error_type:04X})"
    elif 0x8001 <= ext_error_type <= 0x8FFF:
        return f"Reserved (0x{ext_error_type:04X})"
    elif 0x9000 <= ext_error_type <= 0x9FFF:
        return f"Profile-specific (0x{ext_error_type:04X})"
    else:
        return f"Unknown (0x{ext_error_type:04X})"


# =============================================================================
# Parsing Functions
# =============================================================================


def parse_diagnosis_block(
    data: bytes,
    api: int = 0,
    slot: int = 0,
    subslot: int = 0,
) -> DiagnosisData:
    """Parse DiagnosisData block from raw bytes.

    Args:
        data: Raw diagnosis record data
        api: API number
        slot: Slot number
        subslot: Subslot number

    Returns:
        DiagnosisData with parsed entries
    """
    result = DiagnosisData(api=api, slot=slot, subslot=subslot, raw_data=data)

    if len(data) < 6:
        return result

    offset = 0

    # Skip block header if present (BlockType + BlockLength + BlockVersionHigh/Low)
    # BlockType is 2 bytes, BlockLength is 2 bytes, version is 2 bytes
    if len(data) >= 4:
        hdr = DiagBlockHeaderStruct.parse(data[0:4])
        # Check if this looks like a block header
        if hdr.block_type in (0x0010, 0x0011, 0x8010, 0x8011, 0x8012):
            offset = 6  # Skip header

    # Parse diagnosis entries
    while offset + 6 <= len(data):
        # Try to detect UserStructureIdentifier
        # USI is at the start of DiagnosisData block after slot/subslot info

        # First check if we have API/Slot/Subslot header (8 bytes)
        if offset + 8 <= len(data):
            # Try parsing as: API(4) + SlotNumber(2) + SubslotNumber(2)
            location = ApiSlotSubslotStruct.parse(data[offset : offset + 8])

            # Sanity check - API should be small, slot < 0x8000
            if location.api < 0x10000 and location.slot < 0x8000:
                api = location.api
                slot = location.slot
                subslot = location.subslot
                offset += 8

        if offset + 6 > len(data):
            break

        # Read ChannelNumber + ChannelProperties + UserStructureIdentifier
        ch_hdr = ChannelHeaderStruct.parse(data[offset : offset + 6])
        channel_num = ch_hdr.channel_number
        channel_props = ChannelProperties.from_uint16(ch_hdr.channel_properties)
        usi = ch_hdr.usi
        offset += 6

        if usi == UserStructureIdentifier.CHANNEL_DIAGNOSIS:
            # ChannelDiagnosis: ChannelErrorType(2)
            if offset + 2 > len(data):
                break
            body = ChannelDiagBodyStruct.parse(data[offset : offset + 2])
            offset += 2

            entry = ChannelDiagnosis(
                api=api,
                slot=slot,
                subslot=subslot,
                channel_number=channel_num,
                channel_properties=channel_props,
                error_type=body.error_type,
                error_type_name=decode_channel_error_type(body.error_type),
            )
            result.entries.append(entry)

        elif usi == UserStructureIdentifier.EXT_CHANNEL_DIAGNOSIS:
            # ExtChannelDiagnosis: ChannelErrorType(2) + ExtChannelErrorType(2) + ExtChannelAddValue(4)
            if offset + 8 > len(data):
                break
            body = ExtChannelDiagBodyStruct.parse(data[offset : offset + 8])
            offset += 8

            entry = ExtChannelDiagnosis(
                api=api,
                slot=slot,
                subslot=subslot,
                channel_number=channel_num,
                channel_properties=channel_props,
                error_type=body.error_type,
                error_type_name=decode_channel_error_type(body.error_type),
                ext_error_type=body.ext_error_type,
                ext_error_type_name=decode_ext_channel_error_type(
                    body.error_type, body.ext_error_type
                ),
                ext_add_value=body.ext_add_value,
            )
            result.entries.append(entry)

        elif usi == UserStructureIdentifier.QUALIFIED_CHANNEL_DIAGNOSIS:
            # QualifiedChannelDiagnosis: same as Ext + Qualifier(4)
            if offset + 12 > len(data):
                break
            body = QualifiedChannelDiagBodyStruct.parse(data[offset : offset + 12])
            offset += 12

            entry = QualifiedChannelDiagnosis(
                api=api,
                slot=slot,
                subslot=subslot,
                channel_number=channel_num,
                channel_properties=channel_props,
                error_type=body.error_type,
                error_type_name=decode_channel_error_type(body.error_type),
                ext_error_type=body.ext_error_type,
                ext_error_type_name=decode_ext_channel_error_type(
                    body.error_type, body.ext_error_type
                ),
                ext_add_value=body.ext_add_value,
                qualifier=body.qualifier,
            )
            result.entries.append(entry)

        else:
            # Unknown USI - try to create basic entry from what we have
            if offset + 2 <= len(data):
                body = ChannelDiagBodyStruct.parse(data[offset : offset + 2])
                offset += 2

                entry = ChannelDiagnosis(
                    api=api,
                    slot=slot,
                    subslot=subslot,
                    channel_number=channel_num,
                    channel_properties=channel_props,
                    error_type=body.error_type,
                    error_type_name=decode_channel_error_type(body.error_type),
                )
                result.entries.append(entry)
            else:
                break

    logger.debug(f"Parsed {len(result.entries)} diagnosis entries")
    return result


def parse_diagnosis_simple(
    data: bytes,
    api: int = 0,
    slot: int = 0,
    subslot: int = 0,
) -> DiagnosisData:
    """Parse diagnosis data with simpler format detection.

    Tries to parse diagnosis data assuming standard block structure:
    BlockHeader(6) + DiagnosisData

    Args:
        data: Raw diagnosis record data
        api: API number
        slot: Slot number
        subslot: Subslot number

    Returns:
        DiagnosisData with parsed entries
    """
    result = DiagnosisData(api=api, slot=slot, subslot=subslot, raw_data=data)

    if len(data) < 6:
        return result

    # Skip 6-byte block header
    offset = 6

    # Parse all ChannelDiagnosis entries (simple format)
    # Each entry: ChannelNumber(2) + ChannelProperties(2) + ChannelErrorType(2)
    while offset + 6 <= len(data):
        entry_data = SimpleDiagEntryStruct.parse(data[offset : offset + 6])
        channel_num = entry_data.channel_number
        channel_props_raw = entry_data.channel_properties
        error_type = entry_data.error_type
        offset += 6

        # Sanity check
        if error_type == 0 and channel_num == 0 and channel_props_raw == 0:
            break

        channel_props = ChannelProperties.from_uint16(channel_props_raw)

        entry = ChannelDiagnosis(
            api=api,
            slot=slot,
            subslot=subslot,
            channel_number=channel_num,
            channel_properties=channel_props,
            error_type=error_type,
            error_type_name=decode_channel_error_type(error_type),
        )
        result.entries.append(entry)

    return result
