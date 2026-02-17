"""
PROFINET Block Parsing Module.

Provides data classes and parsing functions for PROFINET block structures
extracted from the Wireshark pn_io dissector.

Block structures follow the standard format:
- BlockHeader (6 bytes): Type, Length, Version
- Variable body depending on block type
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import construct as cs

from . import indices

# =============================================================================
# Construct definitions for block-level parsing
# =============================================================================

BlockHeaderStruct = cs.Struct(
    "block_type" / cs.Int16ub,
    "block_length" / cs.Int16ub,
    "version_high" / cs.Int8ub,
    "version_low" / cs.Int8ub,
)

MultipleBlockHeaderBody = cs.Struct(
    "padding" / cs.Bytes(2),
    "api" / cs.Int32ub,
    "slot" / cs.Int16ub,
    "subslot" / cs.Int16ub,
)

PortStatisticStruct = cs.Struct(
    "counter_status" / cs.Int16ub,
    "in_octets" / cs.Int32ub,
    "out_octets" / cs.Int32ub,
    "in_discards" / cs.Int32ub,
    "out_discards" / cs.Int32ub,
    "in_errors" / cs.Int32ub,
    "out_errors" / cs.Int32ub,
)

ModuleDiffBlockHeaderStruct = cs.Struct(
    "block_type" / cs.Int16ub,
    "block_len" / cs.Int16ub,
    "ver_hi" / cs.Int8ub,
    "ver_lo" / cs.Int8ub,
)

ModuleDiffSubmoduleStruct = cs.Struct(
    "subslot_nr" / cs.Int16ub,
    "submodule_ident" / cs.Int32ub,
    "submodule_state" / cs.Int16ub,
)

ModuleDiffModuleStruct = cs.Struct(
    "slot_nr" / cs.Int16ub,
    "module_ident" / cs.Int32ub,
    "module_state" / cs.Int16ub,
    "num_submodules" / cs.Int16ub,
)

WriteResponseBlockStruct = cs.Struct(
    "block_type" / cs.Int16ub,
    "block_len" / cs.Int16ub,
)

SlotSubmoduleStruct = cs.Struct(
    "slot_nr" / cs.Int16ub,
    "module_ident" / cs.Int32ub,
    "num_subslots" / cs.Int16ub,
)

SubslotStruct = cs.Struct(
    "subslot_nr" / cs.Int16ub,
    "submodule_ident" / cs.Int32ub,
)

ExpectedSubmoduleDataDescStruct = cs.Struct(
    "data_description" / cs.Int16ub,
    "submodule_data_length" / cs.Int16ub,
    "length_iocs" / cs.Int8ub,
    "length_iops" / cs.Int8ub,
)

ExpectedSubmoduleEntryStruct = cs.Struct(
    "subslot_number" / cs.Int16ub,
    "submodule_ident_number" / cs.Int32ub,
    "submodule_properties" / cs.Int16ub,
)

ExpectedSubmoduleAPIStruct = cs.Struct(
    "api" / cs.Int32ub,
    "slot_number" / cs.Int16ub,
    "module_ident_number" / cs.Int32ub,
    "module_properties" / cs.Int16ub,
    "num_submodules" / cs.Int16ub,
)

WriteBlockHeaderStruct = cs.Struct(
    "block_type" / cs.Int16ub,
    "block_length" / cs.Int16ub,
    "ver_hi" / cs.Int8ub,
    "ver_lo" / cs.Int8ub,
)

WriteBlockBodyStruct = cs.Struct(
    "seq_num" / cs.Int16ub,
    "ar_uuid" / cs.Bytes(16),
    "api" / cs.Int32ub,
    "slot" / cs.Int16ub,
    "subslot" / cs.Int16ub,
    "padding" / cs.Int16ub,
    "index" / cs.Int16ub,
    "record_data_length" / cs.Int32ub,
    "rw_padding" / cs.Bytes(24),
)

WriteMultipleHeaderStruct = cs.Struct(
    "block_type" / cs.Int16ub,
    "block_length" / cs.Int16ub,
    "ver_hi" / cs.Int8ub,
    "ver_lo" / cs.Int8ub,
    "seq_num" / cs.Int16ub,
    "ar_uuid" / cs.Bytes(16),
    "api" / cs.Int32ub,
    "slot" / cs.Int16ub,
    "subslot" / cs.Int16ub,
    "padding" / cs.Int16ub,
    "index" / cs.Int16ub,
    "record_data_length" / cs.Int32ub,
    "rw_padding" / cs.Bytes(24),
)

# API + NumberOfModules pair used in ModuleDiffBlock and RealIdentificationData
ApiCountStruct = cs.Struct(
    "api" / cs.Int32ub,
    "count" / cs.Int16ub,
)

# Single uint16/uint32 big-endian values (replaces standalone cs.Int16ub/Int32ub.parse() calls)
UInt16ubStruct = cs.Struct("value" / cs.Int16ub)
UInt32ubStruct = cs.Struct("value" / cs.Int32ub)

# MAU type (uint16) for PDPortDataReal
MauTypeStruct = cs.Struct("mau_type" / cs.Int16ub)

# Media type (uint32) for PDPortDataReal
MediaTypeStruct = cs.Struct("media_type" / cs.Int32ub)

# Record data length at fixed offset in WriteMultipleResponse
RecordDataLenStruct = cs.Struct("record_len" / cs.Int32ub)

# Boundaries pair (DomainBoundary + MulticastBoundary) for PDPortDataReal
BoundaryPairStruct = cs.Struct(
    "domain_boundary" / cs.Int32ub,
    "multicast_boundary" / cs.Int32ub,
)

# Slot/Subslot pair for PDPortDataReal
SlotSubslotPairStruct = cs.Struct(
    "slot" / cs.Int16ub,
    "subslot" / cs.Int16ub,
)

# Link state pair for PDPortDataReal
LinkStatePairStruct = cs.Struct(
    "link_state_port" / cs.Int8ub,
    "link_state_link" / cs.Int8ub,
)

# Write response entry fields (parsed at specific offsets within a block)
# Layout: BlockHeader(4) + Version(2) + SeqNum(2) + AR_UUID(16) +
#         API(4) + Slot(2) + Subslot(2) + Padding(2) + Index(2) +
#         RecordDataLength(4) + AddVal1(2) + AddVal2(2) + Status(4) +
#         Padding(8) = 56 bytes total
WriteResEntryStruct = cs.Struct(
    "block_type" / cs.Int16ub,
    "block_len" / cs.Int16ub,
    "ver_hi" / cs.Int8ub,
    "ver_lo" / cs.Int8ub,
    "seq_num" / cs.Int16ub,
    "ar_uuid" / cs.Bytes(16),
    "api" / cs.Int32ub,
    "slot" / cs.Int16ub,
    "subslot" / cs.Int16ub,
    "padding" / cs.Int16ub,
    "index" / cs.Int16ub,
    "record_data_length" / cs.Int32ub,
    "add_val1" / cs.Int16ub,
    "add_val2" / cs.Int16ub,
    "status" / cs.Int32ub,
    "rw_padding" / cs.Bytes(8),
)

# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class BlockHeader:
    """PROFINET block header (6 bytes)."""

    block_type: int
    block_length: int  # Includes version (2 bytes), body = length - 2
    version_high: int
    version_low: int

    @property
    def body_length(self) -> int:
        """Length of block body (excluding version bytes)."""
        return self.block_length - 2 if self.block_length >= 2 else 0

    @property
    def type_name(self) -> str:
        """Human-readable block type name."""
        return indices.get_block_type_name(self.block_type)


@dataclass
class SlotInfo:
    """Slot/subslot discovered from device."""

    slot: int
    subslot: int
    api: int = 0
    module_ident: int = 0
    submodule_ident: int = 0
    blocks: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"SlotInfo(api={self.api}, slot={self.slot}, subslot=0x{self.subslot:04X})"


@dataclass
class PeerInfo:
    """LLDP peer information from PDPortDataReal."""

    port_id: str
    chassis_id: str
    mac_address: bytes

    @property
    def mac_str(self) -> str:
        """MAC address as colon-separated string."""
        return ":".join(f"{b:02x}" for b in self.mac_address)


@dataclass
class PortInfo:
    """Port information from PDPortDataReal (0x020F)."""

    slot: int
    subslot: int
    port_id: str
    mau_type: int
    link_state_port: int
    link_state_link: int
    media_type: int
    peers: List[PeerInfo] = field(default_factory=list)
    domain_boundary: int = 0
    multicast_boundary: int = 0

    @property
    def mau_type_name(self) -> str:
        """Human-readable MAU type."""
        from .rpc import MAU_TYPES

        return MAU_TYPES.get(self.mau_type, f"Unknown({self.mau_type})")

    @property
    def link_state(self) -> str:
        """Human-readable link state."""
        states = {0: "Unknown", 1: "Up", 2: "Down", 3: "Testing"}
        return states.get(self.link_state_link, f"Unknown({self.link_state_link})")


@dataclass
class InterfaceInfo:
    """Interface information from PDInterfaceDataReal (0x0240)."""

    chassis_id: str
    mac_address: bytes
    ip_address: bytes
    subnet_mask: bytes
    gateway: bytes

    @property
    def mac_str(self) -> str:
        """MAC address as colon-separated string."""
        return ":".join(f"{b:02x}" for b in self.mac_address)

    @property
    def ip_str(self) -> str:
        """IP address as dotted string."""
        return ".".join(str(b) for b in self.ip_address)

    @property
    def subnet_str(self) -> str:
        """Subnet mask as dotted string."""
        return ".".join(str(b) for b in self.subnet_mask)

    @property
    def gateway_str(self) -> str:
        """Gateway as dotted string."""
        return ".".join(str(b) for b in self.gateway)


@dataclass
class PDRealData:
    """Parsed PDRealData (0xF841) structure."""

    slots: List[SlotInfo] = field(default_factory=list)
    interface: Optional[InterfaceInfo] = None
    ports: List[PortInfo] = field(default_factory=list)
    raw_blocks: List[Tuple[int, int, int, bytes]] = field(
        default_factory=list
    )  # (api, slot, subslot, data)


@dataclass
class RealIdentificationData:
    """Parsed RealIdentificationData (0xF000/0x0013) structure."""

    slots: List[SlotInfo] = field(default_factory=list)
    version: Tuple[int, int] = (1, 0)


# =============================================================================
# Parsing Functions
# =============================================================================


def parse_block_header(data: bytes, offset: int = 0) -> Tuple[BlockHeader, int]:
    """
    Parse a 6-byte PROFINET block header.

    Args:
        data: Raw bytes containing the block
        offset: Starting offset in data

    Returns:
        Tuple of (BlockHeader, new_offset after header)

    Raises:
        ValueError: If data is too short
    """
    if len(data) < offset + 6:
        raise ValueError(f"Block header requires 6 bytes, got {len(data) - offset}")

    parsed = BlockHeaderStruct.parse(data[offset : offset + 6])

    header = BlockHeader(
        block_type=parsed.block_type,
        block_length=parsed.block_length,
        version_high=parsed.version_high,
        version_low=parsed.version_low,
    )

    return header, offset + 6


def align4(offset: int) -> int:
    """Align offset to 4-byte boundary."""
    return (offset + 3) & ~3


def parse_multiple_block_header(data: bytes, offset: int = 0) -> Tuple[int, int, int, int]:
    """
    Parse MultipleBlockHeader (0x0400) body.

    Format:
        Padding (2 bytes to align to 4)
        API (uint32 BE)
        SlotNr (uint16 BE)
        SubslotNr (uint16 BE)

    Args:
        data: Raw bytes (body after block header)
        offset: Starting offset

    Returns:
        Tuple of (api, slot, subslot, body_offset where nested blocks start)
    """
    if len(data) < offset + 10:
        raise ValueError("MultipleBlockHeader body requires 8 bytes after padding")

    parsed = MultipleBlockHeaderBody.parse(data[offset : offset + 10])

    return parsed.api, parsed.slot, parsed.subslot, offset + 10


def parse_pd_interface_data_real(
    data: bytes, offset: int = 0, block_header_size: int = 6
) -> InterfaceInfo:
    """
    Parse PDInterfaceDataReal (0x0240) block body.

    Format:
        LengthOwnChassisID (uint8)
        OwnChassisID (variable)
        Padding (to 4-byte boundary from block start)
        MACAddress (6 bytes)
        Padding (to 4-byte boundary from block start)
        IPAddress (4 bytes)
        Subnetmask (4 bytes)
        Gateway (4 bytes)

    Args:
        data: Raw bytes (body after block header)
        offset: Starting offset in data
        block_header_size: Size of block header (default 6) for alignment calculation

    Returns:
        InterfaceInfo with parsed data
    """
    start = offset

    def align_from_block(body_offset: int) -> int:
        """Align to 4-byte boundary relative to block start (including header)."""
        block_offset = block_header_size + (body_offset - start)
        aligned_block = align4(block_offset)
        return start + (aligned_block - block_header_size)

    # Read chassis ID length and value
    chassis_len = data[offset]
    offset += 1

    if len(data) < offset + chassis_len:
        raise ValueError("Truncated chassis ID")

    chassis_id = data[offset : offset + chassis_len].decode("latin-1", errors="replace")
    offset += chassis_len

    # Align to 4 bytes from block start
    offset = align_from_block(offset)

    # MAC address (6 bytes)
    if len(data) < offset + 6:
        raise ValueError("Truncated MAC address")
    mac_address = data[offset : offset + 6]
    offset += 6

    # Align to 4 bytes from block start
    offset = align_from_block(offset)

    # IP, Subnet, Gateway (4 bytes each)
    if len(data) < offset + 12:
        raise ValueError("Truncated IP configuration")

    ip_address = data[offset : offset + 4]
    offset += 4
    subnet_mask = data[offset : offset + 4]
    offset += 4
    gateway = data[offset : offset + 4]

    return InterfaceInfo(
        chassis_id=chassis_id,
        mac_address=mac_address,
        ip_address=ip_address,
        subnet_mask=subnet_mask,
        gateway=gateway,
    )


def parse_pd_port_data_real(
    data: bytes, offset: int = 0, slot: int = 0, subslot: int = 0
) -> PortInfo:
    """
    Parse PDPortDataReal (0x020F) block body.

    Format:
        Padding (align to 4)
        SlotNumber (uint16)
        SubslotNumber (uint16)
        LengthOwnPortID (uint8)
        OwnPortID (variable)
        NumberOfPeers (uint8)
        Padding (align to 4)
        [Peer info...]
        MAUType (uint16)
        Padding (align to 4)
        DomainBoundary (uint32)
        MulticastBoundary (uint32)
        LinkStatePort (uint8)
        LinkStateLink (uint8)
        Padding (align to 4)
        MediaType (uint32)

    Args:
        data: Raw bytes (body after block header)
        offset: Starting offset
        slot: Slot number from parent MultipleBlockHeader
        subslot: Subslot number from parent MultipleBlockHeader

    Returns:
        PortInfo with parsed data
    """
    start = offset

    # Padding to align to 4
    offset = align4(offset)

    # Slot/Subslot (may override passed values)
    if len(data) >= offset + 4:
        _ss = SlotSubslotPairStruct.parse(data[offset : offset + 4])
        slot = _ss.slot
        subslot = _ss.subslot
        offset += 4

    # Port ID
    if len(data) < offset + 1:
        return PortInfo(
            slot=slot,
            subslot=subslot,
            port_id="",
            mau_type=0,
            link_state_port=0,
            link_state_link=0,
            media_type=0,
        )

    port_id_len = data[offset]
    offset += 1

    if len(data) < offset + port_id_len:
        port_id = ""
    else:
        port_id = data[offset : offset + port_id_len].decode("latin-1", errors="replace")
        offset += port_id_len

    # Number of peers
    num_peers = 0
    peers = []
    if len(data) > offset:
        num_peers = data[offset]
        offset += 1

    # Align
    offset = start + align4(offset - start)

    # Parse peers
    for _ in range(num_peers):
        if len(data) < offset + 1:
            break

        # Peer port ID
        peer_port_len = data[offset]
        offset += 1
        peer_port_id = ""
        if len(data) >= offset + peer_port_len:
            peer_port_id = data[offset : offset + peer_port_len].decode("latin-1", errors="replace")
            offset += peer_port_len

        # Peer chassis ID
        if len(data) < offset + 1:
            break
        peer_chassis_len = data[offset]
        offset += 1
        peer_chassis_id = ""
        if len(data) >= offset + peer_chassis_len:
            peer_chassis_id = data[offset : offset + peer_chassis_len].decode(
                "latin-1", errors="replace"
            )
            offset += peer_chassis_len

        # Align to 4
        offset = start + align4(offset - start)

        # Peer MAC
        peer_mac = b"\x00" * 6
        if len(data) >= offset + 6:
            peer_mac = data[offset : offset + 6]
            offset += 6

        # Align
        offset = start + align4(offset - start)

        peers.append(
            PeerInfo(port_id=peer_port_id, chassis_id=peer_chassis_id, mac_address=peer_mac)
        )

    # MAU type
    mau_type = 0
    if len(data) >= offset + 2:
        mau_type = MauTypeStruct.parse(data[offset : offset + 2]).mau_type
        offset += 2

    # Align
    offset = start + align4(offset - start)

    # Domain/Multicast boundaries
    domain_boundary = 0
    multicast_boundary = 0
    if len(data) >= offset + 8:
        _bnd = BoundaryPairStruct.parse(data[offset : offset + 8])
        domain_boundary = _bnd.domain_boundary
        multicast_boundary = _bnd.multicast_boundary
        offset += 8

    # Link states
    link_state_port = 0
    link_state_link = 0
    if len(data) >= offset + 2:
        _ls = LinkStatePairStruct.parse(data[offset : offset + 2])
        link_state_port = _ls.link_state_port
        link_state_link = _ls.link_state_link
        offset += 2

    # Align
    offset = start + align4(offset - start)

    # Media type
    media_type = 0
    if len(data) >= offset + 4:
        media_type = MediaTypeStruct.parse(data[offset : offset + 4]).media_type

    return PortInfo(
        slot=slot,
        subslot=subslot,
        port_id=port_id,
        mau_type=mau_type,
        link_state_port=link_state_port,
        link_state_link=link_state_link,
        media_type=media_type,
        peers=peers,
        domain_boundary=domain_boundary,
        multicast_boundary=multicast_boundary,
    )


def parse_pd_real_data(data: bytes) -> PDRealData:
    """
    Parse complete PDRealData (0xF841) response.

    PDRealData contains multiple MultipleBlockHeader blocks, each describing
    a slot/subslot with nested sub-blocks (PDInterfaceDataReal, PDPortDataReal, etc).

    Args:
        data: Raw bytes from reading index 0xF841

    Returns:
        PDRealData with parsed slots, interface, and ports
    """
    result = PDRealData()
    offset = 0

    while offset + 6 <= len(data):
        try:
            header, new_offset = parse_block_header(data, offset)
        except ValueError:
            break

        block_end = new_offset + header.body_length

        if header.block_type == indices.BLOCK_MULTIPLE_HEADER:
            # Parse MultipleBlockHeader to get API/slot/subslot
            try:
                api, slot_nr, subslot_nr, nested_offset = parse_multiple_block_header(
                    data, new_offset
                )

                # Track this slot
                slot_info = SlotInfo(api=api, slot=slot_nr, subslot=subslot_nr)

                # Parse nested blocks within this MultipleBlockHeader
                while nested_offset + 6 <= block_end:
                    try:
                        nested_header, nested_body = parse_block_header(data, nested_offset)
                    except ValueError:
                        break

                    nested_end = nested_body + nested_header.body_length
                    slot_info.blocks.append(nested_header.type_name)

                    # Parse specific block types
                    if nested_header.block_type == indices.BLOCK_PD_INTERFACE_DATA_REAL:
                        try:
                            result.interface = parse_pd_interface_data_real(data, nested_body)
                        except (ValueError, IndexError):
                            pass

                    elif nested_header.block_type == indices.BLOCK_PD_PORT_DATA_REAL:
                        try:
                            port = parse_pd_port_data_real(data, nested_body, slot_nr, subslot_nr)
                            result.ports.append(port)
                        except (ValueError, IndexError):
                            pass

                    nested_offset = nested_end

                result.slots.append(slot_info)
                result.raw_blocks.append((api, slot_nr, subslot_nr, data[new_offset:block_end]))

            except (ValueError, IndexError):
                pass

        offset = block_end

    return result


def parse_real_identification_data(data: bytes) -> RealIdentificationData:
    """
    Parse RealIdentificationData (0xF000 or 0x0013) response.

    Version 1.0:
        NumberOfSlots (uint16)
        For each slot:
            SlotNumber (uint16)
            ModuleIdentNumber (uint32)
            NumberOfSubslots (uint16)
            For each subslot:
                SubslotNumber (uint16)
                SubmoduleIdentNumber (uint32)

    Version 1.1:
        NumberOfAPIs (uint16)
        For each API:
            API (uint32)
            NumberOfSlots (uint16)
            ...same as 1.0

    Args:
        data: Raw bytes from reading index 0xF000

    Returns:
        RealIdentificationData with parsed slot structure
    """
    result = RealIdentificationData()
    offset = 0

    # Parse outer block header if present
    if len(data) >= 6:
        try:
            header, offset = parse_block_header(data, 0)
            result.version = (header.version_high, header.version_low)
        except ValueError:
            offset = 0
            result.version = (1, 0)

    if len(data) < offset + 2:
        return result

    # Version 1.1 has NumberOfAPIs first
    if result.version[0] >= 1 and result.version[1] >= 1:
        num_apis = UInt16ubStruct.parse(data[offset : offset + 2]).value
        offset += 2

        for _ in range(num_apis):
            if len(data) < offset + 6:
                break

            _ac = ApiCountStruct.parse(data[offset : offset + 6])
            api = _ac.api
            num_slots = _ac.count
            offset += 6

            for _ in range(num_slots):
                if len(data) < offset + 8:
                    break

                _s = SlotSubmoduleStruct.parse(data[offset : offset + 8])
                slot_nr = _s.slot_nr
                module_ident = _s.module_ident
                num_subslots = _s.num_subslots
                offset += 8

                for _ in range(num_subslots):
                    if len(data) < offset + 6:
                        break

                    _ss = SubslotStruct.parse(data[offset : offset + 6])
                    offset += 6

                    result.slots.append(
                        SlotInfo(
                            api=api,
                            slot=slot_nr,
                            subslot=_ss.subslot_nr,
                            module_ident=module_ident,
                            submodule_ident=_ss.submodule_ident,
                        )
                    )
    else:
        # Version 1.0 - no API level
        num_slots = UInt16ubStruct.parse(data[offset : offset + 2]).value
        offset += 2

        for _ in range(num_slots):
            if len(data) < offset + 8:
                break

            _s = SlotSubmoduleStruct.parse(data[offset : offset + 8])
            slot_nr = _s.slot_nr
            module_ident = _s.module_ident
            num_subslots = _s.num_subslots
            offset += 8

            for _ in range(num_subslots):
                if len(data) < offset + 6:
                    break

                _ss = SubslotStruct.parse(data[offset : offset + 6])
                offset += 6

                result.slots.append(
                    SlotInfo(
                        api=0,
                        slot=slot_nr,
                        subslot=_ss.subslot_nr,
                        module_ident=module_ident,
                        submodule_ident=_ss.submodule_ident,
                    )
                )

    return result


def parse_port_statistics(data: bytes, offset: int = 0) -> Dict[str, int]:
    """
    Parse PDPortStatistic (0x0251) block body.

    Format:
        CounterStatus (uint16)
        ifInOctets (uint32)
        ifOutOctets (uint32)
        ifInDiscards (uint32)
        ifOutDiscards (uint32)
        ifInErrors (uint32)
        ifOutErrors (uint32)

    Args:
        data: Raw bytes (body after block header)
        offset: Starting offset

    Returns:
        Dictionary with counter names and values
    """
    result = {}

    if len(data) < offset + 26:
        return result

    parsed = PortStatisticStruct.parse(data[offset : offset + 26])

    result = {
        "counter_status": parsed.counter_status,
        "in_octets": parsed.in_octets,
        "out_octets": parsed.out_octets,
        "in_discards": parsed.in_discards,
        "out_discards": parsed.out_discards,
        "in_errors": parsed.in_errors,
        "out_errors": parsed.out_errors,
    }

    return result


# =============================================================================
# ModuleDiffBlock (0x8104) - Response showing module/submodule differences
# =============================================================================


@dataclass
class ModuleDiffSubmodule:
    """Difference info for a single submodule."""

    subslot_number: int = 0
    submodule_ident_number: int = 0
    submodule_state: int = 0

    @property
    def state_name(self) -> str:
        """Human-readable state name."""
        return indices.SUBMODULE_STATE_NAMES.get(
            self.submodule_state, f"Unknown(0x{self.submodule_state:04X})"
        )

    @property
    def is_ok(self) -> bool:
        """True if submodule state is OK (0x0007)."""
        return self.submodule_state == indices.SUBMODULE_STATE_OK


@dataclass
class ModuleDiffModule:
    """Difference info for a single module (slot)."""

    api: int = 0
    slot_number: int = 0
    module_ident_number: int = 0
    module_state: int = 0
    submodules: List[ModuleDiffSubmodule] = field(default_factory=list)

    @property
    def state_name(self) -> str:
        """Human-readable state name."""
        return indices.MODULE_STATE_NAMES.get(
            self.module_state, f"Unknown(0x{self.module_state:04X})"
        )

    @property
    def is_proper(self) -> bool:
        """True if module state is Proper (0x0002)."""
        return self.module_state == indices.MODULE_STATE_PROPER_MODULE


@dataclass
class ModuleDiffBlock:
    """Parsed ModuleDiffBlock (0x8104)."""

    modules: List[ModuleDiffModule] = field(default_factory=list)

    @property
    def all_ok(self) -> bool:
        """Check if all modules and submodules match expected configuration."""
        for mod in self.modules:
            if not mod.is_proper:
                return False
            for sub in mod.submodules:
                if not sub.is_ok:
                    return False
        return True

    def get_mismatches(self) -> List[Tuple[int, int, str]]:
        """Get list of mismatched slots/subslots.

        Returns:
            List of (slot, subslot, state_name) tuples for non-OK items
        """
        mismatches = []
        for mod in self.modules:
            if not mod.is_proper:
                mismatches.append((mod.slot_number, 0, mod.state_name))
            for sub in mod.submodules:
                if not sub.is_ok:
                    mismatches.append((mod.slot_number, sub.subslot_number, sub.state_name))
        return mismatches


def parse_module_diff_block(data: bytes) -> ModuleDiffBlock:
    """Parse ModuleDiffBlock (0x8104) from bytes.

    Args:
        data: Raw bytes of ModuleDiffBlock

    Returns:
        Parsed ModuleDiffBlock

    Raises:
        ValueError: If block type is wrong or data is truncated
    """
    if len(data) < 6:
        return ModuleDiffBlock(modules=[])

    offset = 0

    # Parse block header
    hdr = ModuleDiffBlockHeaderStruct.parse(data[offset : offset + 6])
    offset += 6

    if hdr.block_type != indices.BLOCK_MODULE_DIFF_BLOCK:
        raise ValueError(f"Expected block type 0x8104, got 0x{hdr.block_type:04X}")

    # NumberOfAPIs
    if len(data) < offset + 2:
        return ModuleDiffBlock(modules=[])

    num_apis = UInt16ubStruct.parse(data[offset : offset + 2]).value
    offset += 2

    modules = []

    for _ in range(num_apis):
        if len(data) < offset + 6:
            break

        _ac = ApiCountStruct.parse(data[offset : offset + 6])
        api = _ac.api
        num_modules = _ac.count
        offset += 6

        for _ in range(num_modules):
            if len(data) < offset + 10:
                break

            _mod = ModuleDiffModuleStruct.parse(data[offset : offset + 10])
            offset += 10

            submodules = []
            for _ in range(_mod.num_submodules):
                if len(data) < offset + 8:
                    break

                _sub = ModuleDiffSubmoduleStruct.parse(data[offset : offset + 8])
                offset += 8

                submodules.append(
                    ModuleDiffSubmodule(
                        subslot_number=_sub.subslot_nr,
                        submodule_ident_number=_sub.submodule_ident,
                        submodule_state=_sub.submodule_state,
                    )
                )

            modules.append(
                ModuleDiffModule(
                    api=api,
                    slot_number=_mod.slot_nr,
                    module_ident_number=_mod.module_ident,
                    module_state=_mod.module_state,
                    submodules=submodules,
                )
            )

    return ModuleDiffBlock(modules=modules)


# =============================================================================
# IODWriteMultiple Builder (Index 0xE040)
# =============================================================================


@dataclass
class WriteMultipleResult:
    """Result of a single write in WriteMultiple operation."""

    seq_num: int = 0
    api: int = 0
    slot: int = 0
    subslot: int = 0
    index: int = 0
    status: int = 0
    additional_value1: int = 0
    additional_value2: int = 0

    @property
    def success(self) -> bool:
        """True if write succeeded (status == 0)."""
        return self.status == 0


class IODWriteMultipleBuilder:
    """Builder for IODWriteMultipleReq packets (index 0xE040).

    Handles proper padding between write blocks per IEC 61158-6-10.
    """

    INDEX = 0xE040
    BLOCK_TYPE = 0x0008

    def __init__(self, ar_uuid: bytes, seq_num: int = 0):
        """Initialize builder.

        Args:
            ar_uuid: AR UUID (16 bytes)
            seq_num: Starting sequence number
        """
        self.ar_uuid = ar_uuid
        self.seq_num = seq_num
        self.writes: List[Tuple[int, int, int, int, bytes]] = []

    def add_write(
        self,
        slot: int,
        subslot: int,
        index: int,
        data: bytes,
        api: int = 0,
    ) -> "IODWriteMultipleBuilder":
        """Add a write operation."""
        self.writes.append((api, slot, subslot, index, data))
        return self

    def build(self) -> bytes:
        """Build the complete IODWriteMultipleReq packet."""
        blocks_data = bytearray()

        for i, (api, slot, subslot, index, data) in enumerate(self.writes):
            block = self._build_write_block(i, api, slot, subslot, index, data)
            blocks_data.extend(block)

            # 4-byte padding (except last block)
            if i < len(self.writes) - 1:
                pad_len = (4 - (len(block) % 4)) % 4
                blocks_data.extend(b"\x00" * pad_len)

        header = self._build_header(len(blocks_data))
        return bytes(header) + bytes(blocks_data)

    def _build_write_block(
        self, seq: int, api: int, slot: int, subslot: int, index: int, data: bytes
    ) -> bytes:
        """Build a single IODWriteReq block."""
        block_header = WriteBlockHeaderStruct.build(
            {
                "block_type": 0x0008,
                "block_length": 60,
                "ver_hi": 0x01,
                "ver_lo": 0x00,
            }
        )
        body = WriteBlockBodyStruct.build(
            {
                "seq_num": seq,
                "ar_uuid": self.ar_uuid,
                "api": api,
                "slot": slot,
                "subslot": subslot,
                "padding": 0,
                "index": index,
                "record_data_length": len(data),
                "rw_padding": bytes(24),
            }
        )
        return block_header + body + data

    def _build_header(self, blocks_len: int) -> bytes:
        """Build the outer IODWriteMultipleReq header."""
        return WriteMultipleHeaderStruct.build(
            {
                "block_type": 0x0008,
                "block_length": 60,
                "ver_hi": 0x01,
                "ver_lo": 0x00,
                "seq_num": self.seq_num,
                "ar_uuid": self.ar_uuid,
                "api": 0xFFFFFFFF,
                "slot": 0xFFFF,
                "subslot": 0xFFFF,
                "padding": 0,
                "index": self.INDEX,
                "record_data_length": blocks_len,
                "rw_padding": bytes(24),
            }
        )


def parse_write_multiple_response(data: bytes) -> List[WriteMultipleResult]:
    """Parse IODWriteMultipleRes into individual results."""
    results = []
    if len(data) < 64:
        return results

    record_len = RecordDataLenStruct.parse(data[36:40]).record_len
    offset = 64
    end = min(offset + record_len, len(data))

    while offset + 56 <= end:
        entry = WriteResEntryStruct.parse(data[offset : offset + 56])
        if entry.block_type != 0x8008:
            break

        results.append(
            WriteMultipleResult(
                seq_num=entry.seq_num,
                api=entry.api,
                slot=entry.slot,
                subslot=entry.subslot,
                index=entry.index,
                status=entry.status,
                additional_value1=entry.add_val1,
                additional_value2=entry.add_val2,
            )
        )

        block_size = 4 + entry.block_len
        pad = (4 - (block_size % 4)) % 4
        offset += block_size + pad

    return results


# =============================================================================
# ExpectedSubmodule Structures (0x0104)
# =============================================================================


@dataclass
class ExpectedSubmoduleDataDescription:
    """Describes I/O data for a submodule."""

    data_description: int = 1  # 1=Input, 2=Output
    submodule_data_length: int = 0
    length_iocs: int = 1
    length_iops: int = 1

    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        return ExpectedSubmoduleDataDescStruct.build(
            {
                "data_description": self.data_description,
                "submodule_data_length": self.submodule_data_length,
                "length_iocs": self.length_iocs,
                "length_iops": self.length_iops,
            }
        )


@dataclass
class ExpectedSubmodule:
    """Expected submodule within a slot."""

    subslot_number: int = 0
    submodule_ident_number: int = 0
    submodule_properties: int = 0
    data_descriptions: List[ExpectedSubmoduleDataDescription] = field(default_factory=list)

    @property
    def submodule_type(self) -> int:
        """Get SubmoduleProperties_Type (0=NO_IO, 1=INPUT, 2=OUTPUT, 3=INPUT_OUTPUT)."""
        return self.submodule_properties & 0x03

    def to_bytes(self) -> bytes:
        """Serialize to bytes.

        Per IEC 61158-6-10 and Wireshark/p-net implementations, there is
        NO NumberOfDataDescriptions field. The data descriptions follow
        SubmoduleProperties directly, and their count is implied by
        SubmoduleProperties.type:
          - NO_IO (0): 1 Input DataDescription (data_length=0)
          - INPUT (1): 1 Input DataDescription
          - OUTPUT (2): 1 Output DataDescription
          - INPUT_OUTPUT (3): 2 DataDescriptions (Input + Output)
        """
        result = ExpectedSubmoduleEntryStruct.build(
            {
                "subslot_number": self.subslot_number,
                "submodule_ident_number": self.submodule_ident_number,
                "submodule_properties": self.submodule_properties,
            }
        )
        for dd in self.data_descriptions:
            result += dd.to_bytes()
        return result


@dataclass
class ExpectedSubmoduleAPI:
    """Expected submodules for a specific API/slot."""

    api: int = 0
    slot_number: int = 0
    module_ident_number: int = 0
    module_properties: int = 0
    submodules: List[ExpectedSubmodule] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        result = ExpectedSubmoduleAPIStruct.build(
            {
                "api": self.api,
                "slot_number": self.slot_number,
                "module_ident_number": self.module_ident_number,
                "module_properties": self.module_properties,
                "num_submodules": len(self.submodules),
            }
        )
        for sm in self.submodules:
            result += sm.to_bytes()
        return result


class ExpectedSubmoduleBlockReq:
    """ExpectedSubmoduleBlockReq (0x0104) builder."""

    BLOCK_TYPE = 0x0104

    def __init__(self):
        """Initialize empty builder."""
        self.apis: List[ExpectedSubmoduleAPI] = []

    def add_submodule(
        self,
        api: int,
        slot: int,
        subslot: int,
        module_ident: int,
        submodule_ident: int,
        submodule_type: int = 0,
        input_length: int = 0,
        output_length: int = 0,
    ) -> "ExpectedSubmoduleBlockReq":
        """Add a single submodule."""
        # Find or create API entry
        api_entry = None
        for a in self.apis:
            if a.api == api and a.slot_number == slot:
                api_entry = a
                break

        if api_entry is None:
            api_entry = ExpectedSubmoduleAPI(
                api=api,
                slot_number=slot,
                module_ident_number=module_ident,
                module_properties=0,
                submodules=[],
            )
            self.apis.append(api_entry)

        # Build data descriptions based on submodule type.
        # Per IEC 61158-6-10 and p-net reference:
        # - NO_IO (0): 1 Input DataDescription with data_length=0
        # - INPUT (1): 1 Input DataDescription
        # - OUTPUT (2): 1 Output DataDescription
        # - INPUT_OUTPUT (3): 2 DataDescriptions (Input + Output)
        # Note: p-net always reads at least 1 DataDescription, even for NO_IO.
        dds = []
        if submodule_type == 0:  # NO_IO
            dds.append(ExpectedSubmoduleDataDescription(1, 0, 1, 1))
        elif submodule_type == 1:  # INPUT
            dds.append(ExpectedSubmoduleDataDescription(1, input_length, 1, 1))
        elif submodule_type == 2:  # OUTPUT
            dds.append(ExpectedSubmoduleDataDescription(2, output_length, 1, 1))
        elif submodule_type == 3:  # INPUT_OUTPUT
            dds.append(ExpectedSubmoduleDataDescription(1, input_length, 1, 1))
            dds.append(ExpectedSubmoduleDataDescription(2, output_length, 1, 1))

        api_entry.submodules.append(
            ExpectedSubmodule(subslot, submodule_ident, submodule_type, dds)
        )
        return self

    def to_bytes(self) -> bytes:
        """Build complete ExpectedSubmoduleBlockReq."""
        body = UInt16ubStruct.build({"value": len(self.apis)})
        for api in self.apis:
            body += api.to_bytes()

        block_len = len(body) + 2
        header = WriteBlockHeaderStruct.build(
            {
                "block_type": self.BLOCK_TYPE,
                "block_length": block_len,
                "ver_hi": 0x01,
                "ver_lo": 0x00,
            }
        )
        return header + body
