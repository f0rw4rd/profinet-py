"""
PROFINET DCP (Discovery and Configuration Protocol) implementation.

Provides device discovery and basic configuration operations:
- send_discover(): Multicast discovery request
- read_response(): Collect and parse discovery responses
- get_param(): Read device parameter (name, IP)
- set_param(): Write device parameter

"""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from socket import socket
from typing import Any, Dict, List, Optional, Tuple

import construct as cs

from .exceptions import DCPError
from .protocol import (
    EthernetHeader,
    PNDCPBlock,
    PNDCPBlockRequest,
    PNDCPHeader,
)
from .util import (
    MAX_ETHERNET_FRAME,
    PROFINET_ETHERTYPE,
    VLAN_ETHERTYPE,
    ip2s,
    mac2s,
    max_timeout,
    s2ip,
    s2mac,
)
from .vendors import get_vendor_name

logger = logging.getLogger(__name__)

# =============================================================================
# Construct Struct Definitions for DCP Parsing
# =============================================================================

# Device ID: VendorHigh + VendorLow + DeviceHigh + DeviceLow
DeviceIdStruct = cs.Struct(
    "vendor_high" / cs.Int8ub,
    "vendor_low" / cs.Int8ub,
    "device_high" / cs.Int8ub,
    "device_low" / cs.Int8ub,
)

# Device ID pair for DCP Hello building
DeviceIdPairStruct = cs.Struct(
    "vendor_id" / cs.Int16ub,
    "device_id" / cs.Int16ub,
)

# DCP block entry header: Option + SubOption + Length
DCPBlockEntryStruct = cs.Struct(
    "option" / cs.Int8ub,
    "suboption" / cs.Int8ub,
    "length" / cs.Int16ub,
)

# Single uint16 big-endian value (replaces standalone cs.Int16ub.parse() calls)
UInt16ubStruct = cs.Struct(
    "value" / cs.Int16ub,
)

# =============================================================================
# Constants
# =============================================================================

# DCP multicast addresses per IEC 61158-6-10
DCP_MULTICAST_MAC = "01:0e:cf:00:00:00"  # Identify multicast
DCP_HELLO_MULTICAST_MAC = "01:0e:cf:00:00:01"  # Hello multicast

# DCP Frame IDs
DCP_IDENTIFY_REQUEST_FRAME_ID = 0xFEFE
DCP_IDENTIFY_RESPONSE_FRAME_ID = 0xFEFF
DCP_GET_SET_FRAME_ID = 0xFEFD
DCP_HELLO_FRAME_ID = 0xFEFC

# DCP Service IDs
DCP_SERVICE_ID_GET = 0x03
DCP_SERVICE_ID_SET = 0x04
DCP_SERVICE_ID_IDENTIFY = 0x05
DCP_SERVICE_ID_HELLO = 0x06

# DCP Service Types
DCP_SERVICE_TYPE_REQUEST = 0x00
DCP_SERVICE_TYPE_RESPONSE_SUCCESS = 0x01
DCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED = 0x05

# DCP maximum name length (IEC 61158-6-10)
DCP_MAX_NAME_LENGTH = 240

# DCP Options
DCP_OPTION_IP = 0x01
DCP_OPTION_DEVICE = 0x02
DCP_OPTION_DHCP = 0x03
DCP_OPTION_RESERVED = 0x04
DCP_OPTION_CONTROL = 0x05
DCP_OPTION_DEVICE_INITIATIVE = 0x06
DCP_OPTION_NME = 0x07
DCP_OPTION_ALL = 0xFF

# DCP SubOptions for IP (Option 1)
DCP_SUBOPTION_IP_MAC = 0x01
DCP_SUBOPTION_IP_PARAMETER = 0x02
DCP_SUBOPTION_IP_FULL_SUITE = 0x03

# DCP SubOptions for Device (Option 2)
DCP_SUBOPTION_DEVICE_TYPE = 0x01  # Type of Station / Manufacturer specific
DCP_SUBOPTION_DEVICE_NAME = 0x02  # Name of Station
DCP_SUBOPTION_DEVICE_ID = 0x03  # Device ID (Vendor + Device)
DCP_SUBOPTION_DEVICE_ROLE = 0x04  # Device Role
DCP_SUBOPTION_DEVICE_OPTIONS = 0x05  # Supported options list
DCP_SUBOPTION_DEVICE_ALIAS = 0x06  # Alias Name
DCP_SUBOPTION_DEVICE_INSTANCE = 0x07  # Device Instance
DCP_SUBOPTION_DEVICE_OEM_ID = 0x08  # OEM Device ID
DCP_SUBOPTION_DEVICE_RSI = 0x0A  # RSI Properties

# DCP SubOptions for Control (Option 5)
DCP_SUBOPTION_CONTROL_START = 0x01
DCP_SUBOPTION_CONTROL_STOP = 0x02
DCP_SUBOPTION_CONTROL_SIGNAL = 0x03
DCP_SUBOPTION_CONTROL_RESPONSE = 0x04
DCP_SUBOPTION_CONTROL_RESET_FACTORY = 0x05
DCP_SUBOPTION_CONTROL_RESET_TO_FACTORY = 0x06

# DCP SubOptions for DHCP (Option 3) - Standard DHCP option codes
DCP_SUBOPTION_DHCP_HOSTNAME = 0x0C  # 12 - Host name
DCP_SUBOPTION_DHCP_VENDOR_SPEC = 0x2B  # 43 - Vendor specific
DCP_SUBOPTION_DHCP_SERVER_ID = 0x36  # 54 - Server identifier
DCP_SUBOPTION_DHCP_PARAM_REQ = 0x37  # 55 - Parameter request list
DCP_SUBOPTION_DHCP_CLASS_ID = 0x3C  # 60 - Class identifier
DCP_SUBOPTION_DHCP_CLIENT_ID = 0x3D  # 61 - DHCP client identifier
DCP_SUBOPTION_DHCP_FQDN = 0x51  # 81 - FQDN
DCP_SUBOPTION_DHCP_UUID = 0x61  # 97 - UUID/GUID-based Client
DCP_SUBOPTION_DHCP_CONTROL = 0xFF  # 255 - Control DHCP

# DCP Option 4 is Reserved per IEC 61158-6-10 (LLDP uses its own EtherType 0x88CC)

# DCP SubOptions for DeviceInitiative (Option 6)
DCP_SUBOPTION_DEVICE_INITIATIVE = 0x01

# Manufacturer-specific options (0x80-0xFE per IEC 61158-6-10)
DCP_OPTION_MANUF_MIN = 0x80
DCP_OPTION_MANUF_MAX = 0xFE
DCP_OPTION_MANUF_X80 = 0x80
DCP_OPTION_MANUF_X81 = 0x81
DCP_OPTION_MANUF_X82 = 0x82
DCP_OPTION_MANUF_X83 = 0x83
DCP_OPTION_MANUF_X84 = 0x84
DCP_OPTION_MANUF_X85 = 0x85
DCP_OPTION_MANUF_X86 = 0x86

# Device Role bit masks
DEVICE_ROLE_IO_DEVICE = 0x01
DEVICE_ROLE_IO_CONTROLLER = 0x02
DEVICE_ROLE_IO_MULTIDEVICE = 0x04
DEVICE_ROLE_PN_SUPERVISOR = 0x08

# Device Role names
DEVICE_ROLE_NAMES = {
    DEVICE_ROLE_IO_DEVICE: "IO-Device",
    DEVICE_ROLE_IO_CONTROLLER: "IO-Controller",
    DEVICE_ROLE_IO_MULTIDEVICE: "IO-Multidevice",
    DEVICE_ROLE_PN_SUPERVISOR: "PN-Supervisor",
}


def decode_device_role(role_byte: int) -> List[str]:
    """Decode device role bitmask to list of role names."""
    roles = []
    for mask, name in DEVICE_ROLE_NAMES.items():
        if role_byte & mask:
            roles.append(name)
    return roles if roles else ["Unknown"]


# Option names for display
DCP_OPTION_NAMES = {
    0x01: "IP",
    0x02: "Device",
    0x03: "DHCP",
    0x04: "Reserved",
    0x05: "Control",
    0x06: "DeviceInitiative",
    0x07: "NME",
    0xFF: "All",
}

# Suboption names per option
DCP_SUBOPTION_NAMES = {
    0x01: {  # IP
        0x01: "MAC",
        0x02: "IP",
        0x03: "FullIPSuite",
    },
    0x02: {  # Device
        0x01: "Type",
        0x02: "Name",
        0x03: "DeviceID",
        0x04: "Role",
        0x05: "Options",
        0x06: "Alias",
        0x07: "Instance",
        0x08: "OEM-ID",
        0x0A: "RSI",
    },
    0x03: {  # DHCP
        0x0C: "Hostname",
        0x2B: "VendorSpec",
        0x36: "ServerID",
        0x37: "ParamReq",
        0x3C: "ClassID",
        0x3D: "ClientID",
        0x51: "FQDN",
        0x61: "UUID",
        0xFF: "Control",
    },
    # 0x04 is Reserved per IEC 61158-6-10
    0x05: {  # Control
        0x01: "Start",
        0x02: "Stop",
        0x03: "Signal",
        0x04: "Response",
        0x05: "FactoryReset",
        0x06: "ResetToFactory",
    },
    0x06: {  # DeviceInitiative
        0x01: "Initiative",
    },
}


def get_block_name(option: int, suboption: int) -> str:
    """Get human-readable name for a DCP block."""
    opt_name = DCP_OPTION_NAMES.get(option)
    if opt_name is None:
        if 0x80 <= option <= 0xFE:
            opt_name = f"Vendor-0x{option:02X}"
        else:
            opt_name = f"Opt-0x{option:02X}"

    subopt_names = DCP_SUBOPTION_NAMES.get(option, {})
    subopt_name = subopt_names.get(suboption)
    if subopt_name is None:
        subopt_name = f"0x{suboption:02X}"

    return f"{opt_name}/{subopt_name}"


# Legacy reset mode constants (kept for compatibility)
RESET_MODE_COMMUNICATION = 0x0002
RESET_MODE_APPLICATION = 0x0004
RESET_MODE_ENGINEERING = 0x0008
RESET_MODE_ALL_DATA = 0x0010
RESET_MODE_DEVICE = 0x0020
RESET_MODE_FACTORY = 0x0040


class IPBlockInfo:
    """IP Block Info values (IEC 61158-6-10).

    These values indicate the IP configuration status of a device.
    """

    IP_NOT_SET = 0x0000
    IP_SET = 0x0001
    IP_SET_BY_DHCP = 0x0002
    IP_NOT_SET_CONFLICT = 0x0080
    IP_SET_CONFLICT = 0x0081
    IP_SET_BY_DHCP_CONFLICT = 0x0082

    NAMES = {
        0x0000: "IP not set",
        0x0001: "IP set",
        0x0002: "IP set by DHCP",
        0x0080: "IP not set (address conflict detected)",
        0x0081: "IP set (address conflict detected)",
        0x0082: "IP set by DHCP (address conflict detected)",
    }

    @classmethod
    def get_name(cls, info: int) -> str:
        """Get human-readable name for IP block info."""
        return cls.NAMES.get(info, f"Unknown (0x{info:04X})")

    @classmethod
    def has_conflict(cls, info: int) -> bool:
        """Check if IP block info indicates address conflict."""
        return (info & 0x0080) != 0

    @classmethod
    def is_dhcp(cls, info: int) -> bool:
        """Check if IP was set by DHCP."""
        return (info & 0x0002) != 0


class BlockQualifier:
    """Block Qualifier values for SET operations (IEC 61158-6-10)."""

    TEMPORARY = 0x0000
    PERMANENT = 0x0001

    NAMES = {
        0x0000: "Temporary",
        0x0001: "Permanent",
    }

    @classmethod
    def get_name(cls, qualifier: int) -> str:
        """Get human-readable name for block qualifier."""
        return cls.NAMES.get(qualifier, f"Unknown (0x{qualifier:04X})")


class ResetQualifier:
    """Reset to Factory qualifier values (IEC 61158-6-10)."""

    # Mode 1: Reset application data
    RESET_APPLICATION_DATA = 0x0002
    RESET_APPLICATION_DATA_ALT = 0x0003

    # Mode 2: Reset communication parameters
    RESET_COMMUNICATION_PARAM = 0x0004
    RESET_COMMUNICATION_PARAM_ALT = 0x0005

    # Mode 3: Reset engineering parameters
    RESET_ENGINEERING_PARAM = 0x0006
    RESET_ENGINEERING_PARAM_ALT = 0x0007

    # Mode 4: Reset all stored data
    RESET_ALL_STORED_DATA = 0x0008
    RESET_ALL_STORED_DATA_ALT = 0x0009

    # Mode 5: Reset engineering parameter (alternate)
    RESET_ENGINEERING_PARAM_2 = 0x000A
    RESET_ENGINEERING_PARAM_2_ALT = 0x000B

    # Mode 8: Reset to factory values
    RESET_TO_FACTORY = 0x0010
    RESET_TO_FACTORY_ALT = 0x0011

    # Mode 9: Reset and restore data
    RESET_AND_RESTORE = 0x0012
    RESET_AND_RESTORE_ALT = 0x0013

    NAMES = {
        0x0002: "Reset application data",
        0x0003: "Reset application data",
        0x0004: "Reset communication parameter",
        0x0005: "Reset communication parameter",
        0x0006: "Reset engineering parameter",
        0x0007: "Reset engineering parameter",
        0x0008: "Reset all stored data",
        0x0009: "Reset all stored data",
        0x000A: "Reset engineering parameter",
        0x000B: "Reset engineering parameter",
        0x0010: "Reset to factory values",
        0x0011: "Reset to factory values",
        0x0012: "Reset and restore data",
        0x0013: "Reset and restore data",
    }

    @classmethod
    def get_name(cls, qualifier: int) -> str:
        """Get human-readable name for reset qualifier."""
        return cls.NAMES.get(qualifier, f"Unknown (0x{qualifier:04X})")


class DeviceInitiative:
    """DeviceInitiative values (IEC 61158-6-10)."""

    NO_HELLO = 0x0000
    ISSUE_HELLO = 0x0001

    NAMES = {
        0x0000: "Device does not issue DCP-Hello after power on",
        0x0001: "Device issues DCP-Hello after power on",
    }

    @classmethod
    def get_name(cls, value: int) -> str:
        """Get human-readable name for device initiative value."""
        return cls.NAMES.get(value, f"Unknown (0x{value:04X})")


class DCPResponseCode:
    """DCP response/error codes (IEC 61158-6-10).

    These codes are returned in DCP Set responses to indicate success or failure.
    """

    NO_ERROR = 0x00
    OPTION_NOT_SUPPORTED = 0x01
    SUBOPTION_NOT_SUPPORTED = 0x02
    SUBOPTION_NOT_SET = 0x03
    RESOURCE_ERROR = 0x04
    SET_NOT_POSSIBLE = 0x05
    IN_OPERATION_SET_NOT_POSSIBLE = 0x06

    NAMES = {
        0x00: "No error",
        0x01: "Option not supported",
        0x02: "Suboption not supported or no DataSet available",
        0x03: "Suboption not set",
        0x04: "Resource error",
        0x05: "Set not possible",
        0x06: "In operation, SET not possible",
    }

    @classmethod
    def get_name(cls, code: int) -> str:
        """Get human-readable name for response code."""
        return cls.NAMES.get(code, f"Unknown (0x{code:02X})")


# DCP Block Error codes for SET response (IEC 61158-6-10)
DCP_BLOCK_ERROR_OK = 0x00
DCP_BLOCK_ERROR_OPTION_UNSUPPORTED = 0x01
DCP_BLOCK_ERROR_SUBOPTION_UNSUPPORTED = 0x02
DCP_BLOCK_ERROR_SUBOPTION_NOT_SET = 0x03
DCP_BLOCK_ERROR_RESOURCE = 0x04
DCP_BLOCK_ERROR_SET_NOT_POSSIBLE = 0x05
DCP_BLOCK_ERROR_IN_OPERATION = 0x06

DCP_BLOCK_ERROR_NAMES = {
    DCP_BLOCK_ERROR_OK: "OK",
    DCP_BLOCK_ERROR_OPTION_UNSUPPORTED: "Option not supported",
    DCP_BLOCK_ERROR_SUBOPTION_UNSUPPORTED: "Suboption not supported or no dataset available",
    DCP_BLOCK_ERROR_SUBOPTION_NOT_SET: "Suboption not set",
    DCP_BLOCK_ERROR_RESOURCE: "Resource error",
    DCP_BLOCK_ERROR_SET_NOT_POSSIBLE: "SET not possible by local reasons",
    DCP_BLOCK_ERROR_IN_OPERATION: "In operation, SET not possible",
}


# DCP SET Response block struct: Option(1) + SubOption(1) + Length(2) + BlockError(1) + Padding(1)
DCPSetResponseBlockStruct = cs.Struct(
    "option" / cs.Int8ub,
    "suboption" / cs.Int8ub,
    "length" / cs.Int16ub,
    "block_error" / cs.Int8ub,
    "padding" / cs.Int8ub,
)


@dataclass
class DCPDHCPBlock:
    """Parsed DHCP block from DCP response."""

    suboption: int
    suboption_name: str
    raw_data: bytes
    hostname: Optional[str] = None
    client_id: Optional[bytes] = None
    vendor_specific: Optional[bytes] = None
    fqdn: Optional[str] = None
    uuid: Optional[str] = None

    @classmethod
    def parse(cls, suboption: int, data: bytes) -> DCPDHCPBlock:
        """Parse DHCP block data based on suboption type."""
        suboption_name = DCP_SUBOPTION_NAMES.get(0x03, {}).get(suboption, f"0x{suboption:02X}")
        block = cls(suboption=suboption, suboption_name=suboption_name, raw_data=data)

        if suboption == DCP_SUBOPTION_DHCP_HOSTNAME:
            block.hostname = data.rstrip(b"\x00").decode("utf-8", errors="replace")
        elif suboption == DCP_SUBOPTION_DHCP_CLIENT_ID:
            block.client_id = data
        elif suboption == DCP_SUBOPTION_DHCP_VENDOR_SPEC:
            block.vendor_specific = data
        elif suboption == DCP_SUBOPTION_DHCP_FQDN:
            block.fqdn = data.rstrip(b"\x00").decode("utf-8", errors="replace")
        elif suboption == DCP_SUBOPTION_DHCP_UUID:
            if len(data) >= 16:
                block.uuid = "-".join(
                    [
                        data[0:4].hex(),
                        data[4:6].hex(),
                        data[6:8].hex(),
                        data[8:10].hex(),
                        data[10:16].hex(),
                    ]
                )

        return block


# Parameter name mappings
PARAMS: Dict[str, Tuple[int, int]] = {
    "name": PNDCPBlock.NAME_OF_STATION,
    "ip": PNDCPBlock.IP_ADDRESS,
}


def _generate_xid() -> int:
    """Generate random transaction ID for DCP requests."""
    return secrets.randbelow(0x100000000)


# =============================================================================
# Device Description
# =============================================================================


class DCPDeviceDescription:
    """Parsed PROFINET device information from DCP response.

    Attributes:
        mac: MAC address string
        name: Station name
        device_type: Device type/family (e.g., "S7-1200")
        ip: IP address string
        netmask: Network mask string
        gateway: Gateway address string
        ip_block_info: IP block info value (IPBlockInfo constants)
        ip_conflict: True if IP address conflict detected
        ip_set_by_dhcp: True if IP was set by DHCP
        vendor_high: High byte of vendor ID
        vendor_low: Low byte of vendor ID
        device_high: High byte of device ID
        device_low: Low byte of device ID
        device_role: Device role bitmask
        device_roles: List of role names (e.g., ["IO-Device"])
        device_instance: Device instance (high, low)
        alias_name: Alias name if set
        supported_options: List of supported (option, suboption) tuples
        dhcp_blocks: List of parsed DHCP blocks
        device_initiative: Device initiative value
        issues_hello: True if device issues DCP-Hello after power on
    """

    def __init__(self, mac: bytes, blocks: Dict[Tuple[int, int], bytes]) -> None:
        """Initialize device description from DCP blocks.

        Args:
            mac: Device MAC address (6 bytes)
            blocks: Dictionary of (option, suboption) -> payload mappings

        Raises:
            DCPError: If required blocks are missing
        """
        self.mac = mac2s(mac)

        # Handle device type/family (e.g., "S7-1200")
        type_block = blocks.get(PNDCPBlock.DEVICE_TYPE)
        if type_block is not None:
            self.device_type = type_block.rstrip(b"\x00").decode("utf-8", errors="replace")
        else:
            self.device_type = ""

        # Handle station name (required)
        name_block = blocks.get(PNDCPBlock.NAME_OF_STATION)
        if name_block is not None:
            self.name = name_block.decode("utf-8", errors="replace")
        else:
            self.name = ""
            logger.warning(f"Device {self.mac} has no station name")

        # Handle IP configuration (required)
        ip_block = blocks.get(PNDCPBlock.IP_ADDRESS)
        self.ip_block_info = 0
        self.ip_conflict = False
        self.ip_set_by_dhcp = False
        if ip_block is not None and len(ip_block) >= 12:
            self.ip = s2ip(ip_block[0:4])
            self.netmask = s2ip(ip_block[4:8])
            self.gateway = s2ip(ip_block[8:12])
            # Check for BlockInfo prefix (14 bytes = 2 byte info + 12 byte IP data)
            if len(ip_block) >= 14:
                self.ip_block_info = UInt16ubStruct.parse(ip_block[0:2]).value
                self.ip_conflict = IPBlockInfo.has_conflict(self.ip_block_info)
                self.ip_set_by_dhcp = IPBlockInfo.is_dhcp(self.ip_block_info)
                self.ip = s2ip(ip_block[2:6])
                self.netmask = s2ip(ip_block[6:10])
                self.gateway = s2ip(ip_block[10:14])
        else:
            self.ip = "0.0.0.0"  # nosec B104 — PROFINET default (no IP assigned)
            self.netmask = "0.0.0.0"  # nosec B104
            self.gateway = "0.0.0.0"  # nosec B104
            logger.warning(f"Device {self.mac} has no IP configuration")

        # Handle device ID (optional)
        device_id = blocks.get(PNDCPBlock.DEVICE_ID, b"\x00\x00\x00\x00")
        if len(device_id) >= 4:
            _parsed_dev_id = DeviceIdStruct.parse(device_id[0:4])
            self.vendor_high = _parsed_dev_id.vendor_high
            self.vendor_low = _parsed_dev_id.vendor_low
            self.device_high = _parsed_dev_id.device_high
            self.device_low = _parsed_dev_id.device_low
        else:
            self.vendor_high = 0
            self.vendor_low = 0
            self.device_high = 0
            self.device_low = 0

        # Handle device role (optional) - (2, 4)
        role_block = blocks.get(PNDCPBlock.DEVICE_ROLE)
        if role_block is not None and len(role_block) >= 1:
            self.device_role = role_block[0]
            self.device_roles = decode_device_role(self.device_role)
        else:
            self.device_role = 0
            self.device_roles = []

        # Handle device instance (optional) - (2, 7)
        instance_block = blocks.get((DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_INSTANCE))
        if instance_block is not None and len(instance_block) >= 2:
            self.device_instance = (instance_block[0], instance_block[1])
        else:
            self.device_instance = (0, 0)

        # Handle alias name (optional) - (2, 6)
        alias_block = blocks.get((DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_ALIAS))
        if alias_block is not None:
            self.alias_name = alias_block.rstrip(b"\x00").decode("utf-8", errors="replace")
        else:
            self.alias_name = ""

        # Handle device options (optional) - (2, 5)
        # Each option is 2 bytes: option + suboption
        options_block = blocks.get(PNDCPBlock.DEVICE_OPTIONS)
        self.supported_options: List[Tuple[int, int]] = []
        if options_block is not None and len(options_block) >= 2:
            for i in range(0, len(options_block) - 1, 2):
                opt = options_block[i]
                subopt = options_block[i + 1]
                self.supported_options.append((opt, subopt))

        # Parse DHCP blocks
        self.dhcp_blocks: List[DCPDHCPBlock] = []
        for key, data in blocks.items():
            if isinstance(key, tuple) and len(key) == 2:
                opt, subopt = key
                if opt == DCP_OPTION_DHCP:
                    self.dhcp_blocks.append(DCPDHCPBlock.parse(subopt, data))

        # Option 0x04 is Reserved per IEC 61158-6-10
        # Any data received under this option is stored as raw blocks

        # Handle DeviceInitiative (optional) - (6, 1)
        initiative_block = blocks.get(
            (DCP_OPTION_DEVICE_INITIATIVE, DCP_SUBOPTION_DEVICE_INITIATIVE)
        )
        self.device_initiative = 0
        self.issues_hello = False
        if initiative_block is not None and len(initiative_block) >= 2:
            self.device_initiative = UInt16ubStruct.parse(initiative_block[0:2]).value
            self.issues_hello = self.device_initiative == DeviceInitiative.ISSUE_HELLO

        # Store all raw blocks for unknown/vendor-specific options
        self.raw_blocks: Dict[Tuple[int, int], bytes] = {}
        known_blocks = {
            PNDCPBlock.IP_ADDRESS,
            PNDCPBlock.DEVICE_TYPE,
            PNDCPBlock.NAME_OF_STATION,
            PNDCPBlock.DEVICE_ID,
            PNDCPBlock.DEVICE_ROLE,
            PNDCPBlock.DEVICE_OPTIONS,
            PNDCPBlock.DEVICE_ALIAS,
            PNDCPBlock.DEVICE_INSTANCE,
            (DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_INSTANCE),
            (DCP_OPTION_DEVICE, DCP_SUBOPTION_DEVICE_ALIAS),
            (DCP_OPTION_DEVICE_INITIATIVE, DCP_SUBOPTION_DEVICE_INITIATIVE),
        }
        # Exclude DHCP blocks from raw_blocks
        for key, value in blocks.items():
            if isinstance(key, tuple) and key not in known_blocks:
                opt, _ = key
                if opt != DCP_OPTION_DHCP:
                    self.raw_blocks[key] = value

    @property
    def vendor_id(self) -> int:
        """Get 16-bit vendor ID."""
        return (self.vendor_high << 8) | self.vendor_low

    @property
    def device_id(self) -> int:
        """Get 16-bit device ID."""
        return (self.device_high << 8) | self.device_low

    @property
    def vendor_name(self) -> str:
        """Get vendor name from ID lookup."""
        return get_vendor_name(self.vendor_id)

    def __repr__(self) -> str:
        return (
            f"DCPDeviceDescription(name={self.name!r}, type={self.device_type!r}, "
            f"ip={self.ip}, mac={self.mac}, vendor={self.vendor_name!r})"
        )

    def __str__(self) -> str:
        lines = [
            f"PROFINET Device: {self.name}",
            f"  MAC:     {self.mac}",
        ]
        if self.device_type:
            lines.append(f"  Type:    {self.device_type}")
        lines.extend(
            [
                f"  IP:      {self.ip}",
                f"  Netmask: {self.netmask}",
                f"  Gateway: {self.gateway}",
            ]
        )
        # IP Block Info
        if self.ip_block_info:
            lines.append(f"  IP Info: {IPBlockInfo.get_name(self.ip_block_info)}")
        if self.ip_conflict:
            lines.append("  Warning: IP address conflict detected")
        if self.ip_set_by_dhcp:
            lines.append("  IP Source: DHCP")
        lines.extend(
            [
                f"  Vendor:  {self.vendor_name} (0x{self.vendor_id:04X})",
                f"  Device:  0x{self.device_id:04X}",
            ]
        )
        if self.device_roles:
            lines.append(f"  Role:    {', '.join(self.device_roles)}")
        if self.device_instance != (0, 0):
            lines.append(f"  Instance: {self.device_instance[0]}.{self.device_instance[1]}")
        if self.alias_name:
            lines.append(f"  Alias:   {self.alias_name}")
        # Device Initiative
        if self.device_initiative:
            lines.append(f"  Initiative: {DeviceInitiative.get_name(self.device_initiative)}")
        if self.supported_options:
            opts = [get_block_name(o, s) for o, s in self.supported_options]
            lines.append(f"  Supports: {', '.join(opts)}")
        # DHCP blocks
        if self.dhcp_blocks:
            lines.append("  DHCP:")
            for block in self.dhcp_blocks:
                if block.hostname:
                    lines.append(f"    Hostname: {block.hostname}")
                elif block.fqdn:
                    lines.append(f"    FQDN: {block.fqdn}")
                elif block.uuid:
                    lines.append(f"    UUID: {block.uuid}")
                else:
                    lines.append(f"    {block.suboption_name}: {block.raw_data.hex()}")
        if self.raw_blocks:
            for (opt, subopt), data in self.raw_blocks.items():
                lines.append(f"  Unknown ({opt},{subopt}): {data.hex()}")
        return "\n".join(lines)


# =============================================================================
# DCP Operations
# =============================================================================


def get_param(
    sock: socket,
    src: bytes,
    target: str,
    param: str,
    timeout_sec: int = 5,
) -> Optional[bytes]:
    """Read a parameter from a PROFINET device.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        target: Target device MAC address string
        param: Parameter name ("name" or "ip")
        timeout_sec: Timeout in seconds

    Returns:
        Parameter value as bytes, or None if not found

    Raises:
        DCPError: If parameter name is unknown
    """
    if param not in PARAMS:
        raise DCPError(f"Unknown parameter: {param!r}. Valid: {list(PARAMS.keys())}")

    dst = s2mac(target)
    param_tuple = PARAMS[param]
    xid = _generate_xid()

    block = PNDCPBlockRequest(param_tuple[0], param_tuple[1], 0, payload=b"")
    dcp = PNDCPHeader(
        DCP_GET_SET_FRAME_ID,
        PNDCPHeader.GET,
        PNDCPHeader.REQUEST,
        xid,
        0,
        2,
        payload=block,
    )
    eth = EthernetHeader(dst, src, PROFINET_ETHERTYPE, payload=dcp)

    sock.send(bytes(eth))

    responses = read_response(sock, src, timeout_sec=timeout_sec, once=True)
    if responses:
        first_response = list(responses.values())[0]
        return first_response.get(param_tuple)
    return None


def _parse_set_response(data: bytes, src_mac: bytes) -> int:
    """Parse a DCP SET response and extract the block error code.

    DCP SET responses contain a Control/Response block (option 0x05, suboption 0x04)
    with a BlockError field indicating success or failure.

    Args:
        data: Raw Ethernet frame bytes
        src_mac: Our source MAC address for filtering

    Returns:
        Block error code (0x00 = success)

    Raises:
        DCPError: If response cannot be parsed
    """
    if len(data) < 14:
        raise DCPError("DCP SET response too short")

    try:
        eth = EthernetHeader(data)
    except ValueError as e:
        raise DCPError(f"Failed to parse Ethernet header: {e}") from e

    # Handle VLAN-tagged frames
    payload = eth.payload
    if eth.type == VLAN_ETHERTYPE:
        if len(payload) < 4:
            raise DCPError("VLAN frame too short")
        inner_type = (payload[2] << 8) | payload[3]
        if inner_type != PROFINET_ETHERTYPE:
            raise DCPError(f"Unexpected inner EtherType: 0x{inner_type:04X}")
        payload = payload[4:]
    elif eth.type != PROFINET_ETHERTYPE:
        raise DCPError(f"Unexpected EtherType: 0x{eth.type:04X}")

    try:
        dcp_hdr = PNDCPHeader(payload)
    except ValueError as e:
        raise DCPError(f"Failed to parse DCP header: {e}") from e

    # Check service type for response
    if dcp_hdr.service_type == DCP_SERVICE_TYPE_RESPONSE_UNSUPPORTED:
        raise DCPError("DCP SET: service not supported by device")

    if dcp_hdr.service_type != DCP_SERVICE_TYPE_RESPONSE_SUCCESS:
        raise DCPError(f"DCP SET: unexpected service_type 0x{dcp_hdr.service_type:02X}")

    # Parse response blocks to find Control/Response block (option=5, suboption=4)
    blocks_data = dcp_hdr.payload
    remaining = dcp_hdr.length

    while remaining > 4:
        try:
            entry = DCPBlockEntryStruct.parse(blocks_data[:4])
        except (cs.ConstructError, IndexError):
            break

        block_payload = blocks_data[4 : 4 + entry.length]

        if entry.option == DCP_OPTION_CONTROL and entry.suboption == DCP_SUBOPTION_CONTROL_RESPONSE:
            # Control/Response block: Option(1) + SubOption(1) + BlockError(1)
            if len(block_payload) >= 3:
                # Payload: OptionForResponse(1) + SubOptionForResponse(1) + BlockError(1)
                block_error = block_payload[2]
                return block_error
            elif len(block_payload) >= 1:
                return block_payload[0]
            return DCP_BLOCK_ERROR_OK

        # Move to next block (2-byte aligned)
        block_len = 4 + entry.length
        if entry.length % 2 == 1:
            block_len += 1
        blocks_data = blocks_data[block_len:]
        remaining -= block_len

    # No Control/Response block found - treat as success (some devices omit it)
    logger.debug("DCP SET response: no Control/Response block found, assuming success")
    return DCP_BLOCK_ERROR_OK


def _recv_set_response(sock: socket, src_mac: bytes, timeout_sec: int) -> int:
    """Receive and parse a DCP SET response, filtering out non-response frames.

    On Windows (Npcap), raw sockets receive copies of outgoing frames, so we
    must loop and skip packets that are not actual responses addressed to us.

    Args:
        sock: Raw Ethernet socket
        src_mac: Our source MAC address (6 bytes) for filtering
        timeout_sec: Maximum time to wait for the response

    Returns:
        Block error code (0x00 = success)

    Raises:
        DCPError: If response indicates an error
        TimeoutError: If no valid response received within timeout
    """
    sock.settimeout(2.0)
    with max_timeout(timeout_sec) as timer:
        while not timer.timed_out:
            try:
                data = sock.recv(MAX_ETHERNET_FRAME)
            except TimeoutError:
                continue
            except OSError as e:
                logger.debug(f"Socket error during SET recv: {e}")
                continue

            if len(data) < 14:
                continue

            # Parse Ethernet header
            try:
                eth = EthernetHeader(data)
            except ValueError:
                continue

            # Skip packets not addressed to us (including our own sent frames)
            if eth.dst != src_mac:
                continue

            # Must be PROFINET EtherType (handle VLAN too)
            payload = eth.payload
            if eth.type == VLAN_ETHERTYPE:
                if len(payload) < 4:
                    continue
                inner_type = (payload[2] << 8) | payload[3]
                if inner_type != PROFINET_ETHERTYPE:
                    continue
            elif eth.type != PROFINET_ETHERTYPE:
                continue

            # Try to parse as a SET response
            try:
                return _parse_set_response(data, src_mac)
            except DCPError as e:
                # If it's a non-response frame (e.g. our own request echoed back),
                # skip it and keep waiting
                if "unexpected service_type" in str(e):
                    logger.debug(f"Skipping non-response frame: {e}")
                    continue
                raise

    raise TimeoutError("No DCP SET response received")


def set_param(
    sock: socket,
    src: bytes,
    target: str,
    param: str,
    value: str,
    timeout_sec: int = 5,
) -> bool:
    """Write a parameter to a PROFINET device.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        target: Target device MAC address string
        param: Parameter name ("name" or "ip")
        value: New parameter value
        timeout_sec: Timeout in seconds

    Returns:
        True on success, False if timeout

    Raises:
        DCPError: If parameter name is unknown or device returns error
        ValueError: If name exceeds DCP_MAX_NAME_LENGTH (240 chars)
    """
    if param not in PARAMS:
        raise DCPError(f"Unknown parameter: {param!r}. Valid: {list(PARAMS.keys())}")

    # Validate name length per IEC 61158-6-10
    if param == "name" and len(value) > DCP_MAX_NAME_LENGTH:
        raise ValueError(
            f"Station name exceeds maximum length: {len(value)} > {DCP_MAX_NAME_LENGTH}"
        )

    dst = s2mac(target)
    param_tuple = PARAMS[param]
    value_bytes = bytes(value, encoding="ascii")
    xid = _generate_xid()

    # Add padding for block qualifier (2 bytes)
    block = PNDCPBlockRequest(
        param_tuple[0],
        param_tuple[1],
        len(value_bytes) + 2,
        payload=bytes([0x00, 0x00]) + value_bytes,
    )

    # Calculate length with padding
    padding = 1 if len(value_bytes) % 2 == 1 else 0
    dcp = PNDCPHeader(
        DCP_GET_SET_FRAME_ID,
        PNDCPHeader.SET,
        PNDCPHeader.REQUEST,
        xid,
        0,
        len(value_bytes) + 6 + padding,
        payload=block,
    )
    eth = EthernetHeader(dst, src, PROFINET_ETHERTYPE, payload=dcp)

    sock.send(bytes(eth))

    # Wait for and validate response (loops to skip echoed frames on Windows)
    try:
        block_error = _recv_set_response(sock, src, timeout_sec)
        if block_error != DCP_BLOCK_ERROR_OK:
            error_name = DCP_BLOCK_ERROR_NAMES.get(
                block_error, f"Unknown error (0x{block_error:02X})"
            )
            raise DCPError(f"DCP SET failed for {param!r}: {error_name}")
        # Wait for device to process
        time.sleep(2)
        return True
    except TimeoutError:
        logger.warning(f"No response from {target} for set_param")
        return False


def set_ip(
    sock: socket,
    src: bytes,
    target: str,
    ip: str,
    netmask: str,
    gateway: str,
    permanent: bool = False,
    timeout_sec: int = 5,
) -> bool:
    """Set IP configuration on a PROFINET device via DCP.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        target: Target device MAC address string
        ip: New IP address (e.g., "192.168.10.3")
        netmask: Subnet mask (e.g., "255.255.255.0")
        gateway: Gateway address (e.g., "192.168.10.1")
        permanent: If True, save IP permanently; if False, temporary (default)
        timeout_sec: Timeout in seconds

    Returns:
        True if response received, False if timeout
    """
    dst = s2mac(target)
    xid = _generate_xid()

    # Convert IP strings to bytes (4 bytes each)
    def ip_to_bytes(ip_str: str) -> bytes:
        parts = ip_str.split(".")
        return bytes([int(p) for p in parts])

    ip_bytes = ip_to_bytes(ip)
    netmask_bytes = ip_to_bytes(netmask)
    gateway_bytes = ip_to_bytes(gateway)

    # IP block payload: 2 bytes qualifier + 4 IP + 4 netmask + 4 gateway = 14 bytes
    value_bytes = ip_bytes + netmask_bytes + gateway_bytes

    # Use appropriate qualifier based on permanent flag
    qualifier = BlockQualifier.PERMANENT if permanent else BlockQualifier.TEMPORARY
    qualifier_bytes = UInt16ubStruct.build({"value": qualifier})

    block = PNDCPBlockRequest(
        PNDCPBlock.IP_ADDRESS[0],  # Option (0x01 = IP)
        PNDCPBlock.IP_ADDRESS[1],  # Suboption (0x02 = IP Suite)
        len(value_bytes) + 2,  # Length includes 2-byte qualifier
        payload=qualifier_bytes + value_bytes,
    )

    # Calculate length with padding (blocks are 2-byte aligned)
    padding = 0 if len(value_bytes) % 2 == 0 else 1
    dcp = PNDCPHeader(
        DCP_GET_SET_FRAME_ID,
        PNDCPHeader.SET,
        PNDCPHeader.REQUEST,
        xid,
        0,
        len(value_bytes) + 6 + padding,
        payload=block,
    )
    eth = EthernetHeader(dst, src, PROFINET_ETHERTYPE, payload=dcp)

    sock.send(bytes(eth))

    # Wait for and validate response (loops to skip echoed frames on Windows)
    try:
        block_error = _recv_set_response(sock, src, timeout_sec)
        if block_error != DCP_BLOCK_ERROR_OK:
            error_name = DCP_BLOCK_ERROR_NAMES.get(
                block_error, f"Unknown error (0x{block_error:02X})"
            )
            raise DCPError(f"DCP SET IP failed: {error_name}")
        # Wait for device to process
        time.sleep(2)
        return True
    except TimeoutError:
        logger.warning(f"No response from {target} for set_ip")
        return False


def send_discover(sock: socket, src: bytes, response_delay: int = 0x0080) -> None:
    """Send DCP Identify multicast request.

    Sends an Identify request to the PROFINET multicast address
    to discover all devices on the network.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        response_delay: Max response delay in 10ms units (default: 0x0080 = 1.28s)
    """
    xid = _generate_xid()

    block = PNDCPBlockRequest(0xFF, 0xFF, 0, payload=b"")
    dcp = PNDCPHeader(
        DCP_IDENTIFY_REQUEST_FRAME_ID,
        PNDCPHeader.IDENTIFY,
        PNDCPHeader.REQUEST,
        xid,
        response_delay,
        len(block),
        payload=block,
    )
    eth = EthernetHeader(
        s2mac(DCP_MULTICAST_MAC),
        src,
        PROFINET_ETHERTYPE,
        payload=dcp,
    )

    sock.send(bytes(eth))
    logger.debug(f"Sent DCP Identify request (xid=0x{xid:08X})")


def send_request(
    sock: socket,
    src: bytes,
    block_type: Tuple[int, int],
    value: bytes,
) -> None:
    """Send DCP Identify request with specific filter.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        block_type: (option, suboption) tuple to filter
        value: Filter value bytes
    """
    xid = _generate_xid()

    block = PNDCPBlockRequest(block_type[0], block_type[1], len(value), payload=value)
    dcp = PNDCPHeader(
        DCP_IDENTIFY_REQUEST_FRAME_ID,
        PNDCPHeader.IDENTIFY,
        PNDCPHeader.REQUEST,
        xid,
        0x0080,  # Response delay in 10ms units (1.28s), required for devices to respond
        len(block),
        payload=block,
    )
    eth = EthernetHeader(
        s2mac(DCP_MULTICAST_MAC),
        src,
        PROFINET_ETHERTYPE,
        payload=dcp,
    )

    sock.send(bytes(eth))
    logger.debug(f"Sent DCP request for {block_type} (xid=0x{xid:08X})")


def read_response(
    sock: socket,
    my_mac: bytes,
    timeout_sec: int = 20,
    once: bool = False,
    debug: bool = False,
    expected_xid: Optional[int] = None,
) -> Dict[bytes, Dict[Any, Any]]:
    """Read and parse DCP responses.

    Args:
        sock: Raw Ethernet socket
        my_mac: Our MAC address (6 bytes) for filtering
        timeout_sec: Maximum time to wait for responses
        once: If True, return after first response
        debug: If True, log debug information
        expected_xid: If set, only accept responses matching this transaction ID

    Returns:
        Dictionary mapping MAC addresses to parsed block data
    """
    result: Dict[bytes, Dict[Any, Any]] = {}
    sock.settimeout(2.0)

    try:
        with max_timeout(timeout_sec) as timer:
            while not timer.timed_out:
                try:
                    data = sock.recv(MAX_ETHERNET_FRAME)
                except TimeoutError:
                    continue
                except OSError as e:
                    logger.debug(f"Socket error during receive: {e}")
                    continue

                if len(data) < 14:  # Minimum Ethernet header
                    continue

                # Parse Ethernet header
                try:
                    eth = EthernetHeader(data)
                except ValueError as e:
                    logger.debug(f"Failed to parse Ethernet header: {e}")
                    continue

                # Filter: only packets to us
                if eth.dst != my_mac:
                    continue

                # Handle both VLAN-tagged and non-VLAN frames
                # Some devices (e.g., Siemens S7-1200) respond with VLAN tags
                payload = eth.payload
                if eth.type == VLAN_ETHERTYPE:
                    # VLAN header: 2 bytes TCI + 2 bytes inner ethertype
                    if len(payload) < 4:
                        continue
                    inner_type = (payload[2] << 8) | payload[3]
                    if inner_type != PROFINET_ETHERTYPE:
                        continue
                    payload = payload[4:]  # Skip VLAN header
                elif eth.type != PROFINET_ETHERTYPE:
                    continue

                if debug:
                    logger.info(f"DCP response from {mac2s(eth.src)}")

                # Parse DCP header
                try:
                    dcp = PNDCPHeader(payload)
                except ValueError as e:
                    logger.debug(f"Failed to parse DCP header: {e}")
                    continue

                # Filter: only DCP responses
                if dcp.service_type != PNDCPHeader.RESPONSE:
                    continue

                # Validate transaction ID if specified
                if expected_xid is not None and dcp.xid != expected_xid:
                    logger.debug(
                        f"Ignoring response with wrong XID "
                        f"(got 0x{dcp.xid:08X}, expected 0x{expected_xid:08X})"
                    )
                    continue

                # Parse DCP blocks
                blocks = dcp.payload
                length = dcp.length
                parsed: Dict[Any, Any] = {}

                while length > 6:
                    try:
                        block = PNDCPBlock(blocks)
                    except ValueError as e:
                        logger.debug(f"Failed to parse DCP block: {e}")
                        break

                    block_option = (block.option, block.suboption)
                    parsed[block_option] = block.payload

                    if block_option == PNDCPBlock.NAME_OF_STATION:
                        if debug:
                            logger.info(
                                f"  Name: {block.payload.decode('utf-8', errors='replace')}"
                            )
                        parsed["name"] = block.payload

                    elif block_option == PNDCPBlock.IP_ADDRESS:
                        if debug:
                            logger.info(f"  IP: {s2ip(block.payload[0:4])}")
                        parsed["ip"] = s2ip(block.payload[0:4])

                    elif block_option == PNDCPBlock.DEVICE_ID:
                        parsed["devId"] = block.payload

                    # Handle padding (blocks are 2-byte aligned)
                    block_len = block.length
                    if block_len % 2 == 1:
                        block_len += 1

                    # Move to next block (4 bytes header + payload + padding)
                    blocks = blocks[block_len + 4 :]
                    length -= 4 + block_len

                result[eth.src] = parsed

                if once:
                    break

    except TimeoutError:
        pass

    logger.debug(f"DCP discovery found {len(result)} devices")
    return result


def send_hello(
    sock: socket,
    src: bytes,
    station_name: str,
    ip: str = "0.0.0.0",  # nosec B104 — PROFINET default (no IP assigned)
    netmask: str = "0.0.0.0",  # nosec B104
    gateway: str = "0.0.0.0",  # nosec B104
    device_id: Tuple[int, int] = (0, 0),
    device_role: int = DEVICE_ROLE_IO_DEVICE,
) -> None:
    """Send DCP Hello multicast announcement.

    This allows a device to announce its presence after power-on.
    Used by devices with DeviceInitiative = 0x0001.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        station_name: Device station name
        ip: IP address (default: "0.0.0.0")
        netmask: Subnet mask (default: "0.0.0.0")
        gateway: Gateway address (default: "0.0.0.0")
        device_id: (vendor_id, device_id) tuple (default: (0, 0))
        device_role: Device role bitmask (default: IO-Device)
    """
    xid = _generate_xid()

    # Build blocks for Hello PDU
    blocks_data = b""

    # Name of Station block
    name_bytes = station_name.encode("ascii")
    name_block = PNDCPBlockRequest(
        DCP_OPTION_DEVICE,
        DCP_SUBOPTION_DEVICE_NAME,
        len(name_bytes),
        payload=name_bytes,
    )
    blocks_data += bytes(name_block)
    if len(name_bytes) % 2 == 1:
        blocks_data += b"\x00"  # Padding

    # IP block
    ip_bytes = ip2s(ip) + ip2s(netmask) + ip2s(gateway)
    ip_block = PNDCPBlockRequest(
        DCP_OPTION_IP,
        DCP_SUBOPTION_IP_PARAMETER,
        len(ip_bytes),
        payload=ip_bytes,
    )
    blocks_data += bytes(ip_block)

    # Device ID block
    device_id_bytes = DeviceIdPairStruct.build(
        {"vendor_id": device_id[0], "device_id": device_id[1]}
    )
    device_id_block = PNDCPBlockRequest(
        DCP_OPTION_DEVICE,
        DCP_SUBOPTION_DEVICE_ID,
        len(device_id_bytes),
        payload=device_id_bytes,
    )
    blocks_data += bytes(device_id_block)

    # Device Role block
    role_bytes = bytes([device_role, 0x00])
    role_block = PNDCPBlockRequest(
        DCP_OPTION_DEVICE,
        DCP_SUBOPTION_DEVICE_ROLE,
        len(role_bytes),
        payload=role_bytes,
    )
    blocks_data += bytes(role_block)

    # Device Initiative block
    initiative_bytes = UInt16ubStruct.build({"value": DeviceInitiative.ISSUE_HELLO})
    initiative_block = PNDCPBlockRequest(
        DCP_OPTION_DEVICE_INITIATIVE,
        DCP_SUBOPTION_DEVICE_INITIATIVE,
        len(initiative_bytes),
        payload=initiative_bytes,
    )
    blocks_data += bytes(initiative_block)

    # Build DCP header
    dcp = PNDCPHeader(
        DCP_HELLO_FRAME_ID,
        PNDCPHeader.HELLO,
        PNDCPHeader.REQUEST,
        xid,
        0,  # No response delay for Hello
        len(blocks_data),
        payload=blocks_data,
    )

    # Send to DCP Hello multicast address (01:0e:cf:00:00:01)
    eth = EthernetHeader(
        s2mac(DCP_HELLO_MULTICAST_MAC),
        src,
        PROFINET_ETHERTYPE,
        payload=dcp,
    )

    sock.send(bytes(eth))
    logger.debug(f"Sent DCP Hello (station={station_name}, xid=0x{xid:08X})")


def receive_hello(
    sock: socket,
    my_mac: bytes,
    timeout_sec: int = 10,
    callback: Optional[Callable[[DCPDeviceDescription], None]] = None,
) -> List[DCPDeviceDescription]:
    """Listen for DCP Hello announcements.

    Args:
        sock: Raw Ethernet socket
        my_mac: Our MAC address (6 bytes) for filtering
        timeout_sec: Maximum time to wait
        callback: Optional callback for each Hello received

    Returns:
        List of DCPDeviceDescription objects from Hello PDUs
    """
    devices: List[DCPDeviceDescription] = []
    sock.settimeout(2.0)

    try:
        with max_timeout(timeout_sec) as timer:
            while not timer.timed_out:
                try:
                    data = sock.recv(MAX_ETHERNET_FRAME)
                except TimeoutError:
                    continue

                if len(data) < 14:
                    continue

                eth = EthernetHeader(data)

                # Handle VLAN
                payload = eth.payload
                if eth.type == VLAN_ETHERTYPE:
                    if len(payload) < 4:
                        continue
                    inner_type = (payload[2] << 8) | payload[3]
                    if inner_type != PROFINET_ETHERTYPE:
                        continue
                    payload = payload[4:]
                elif eth.type != PROFINET_ETHERTYPE:
                    continue

                if len(payload) < 10:
                    continue

                try:
                    dcp = PNDCPHeader(payload)
                except (ValueError, cs.ConstructError):
                    continue

                # Filter for Hello requests only
                if dcp.service_id != PNDCPHeader.HELLO:
                    continue
                if dcp.service_type != PNDCPHeader.REQUEST:
                    continue

                # Parse blocks using DCPBlockEntryStruct
                blocks: Dict[Tuple[int, int], bytes] = {}
                offset = 0
                dcp_payload = dcp.payload
                while offset + 4 <= len(dcp_payload):
                    try:
                        entry = DCPBlockEntryStruct.parse(dcp_payload[offset : offset + 4])
                        block_data = dcp_payload[offset + 4 : offset + 4 + entry.length]
                        blocks[(entry.option, entry.suboption)] = block_data
                        # Move to next block (2-byte aligned)
                        block_len = 4 + entry.length
                        if entry.length % 2 == 1:
                            block_len += 1
                        offset += block_len
                    except (IndexError, cs.ConstructError):
                        break

                try:
                    device = DCPDeviceDescription(eth.src, blocks)
                    devices.append(device)

                    if callback:
                        callback(device)

                    logger.debug(f"Received DCP Hello from {device.name}")
                except Exception as e:
                    logger.warning(f"Failed to parse Hello from {mac2s(eth.src)}: {e}")

    except TimeoutError:
        pass

    return devices


def signal_device(
    sock: socket,
    src: bytes,
    target: str,
    duration_ms: int = 3000,
    timeout_sec: int = 5,
) -> bool:
    """Send DCP Signal command to flash device LEDs.

    This sends a Control/Signal request that causes the device to
    flash its identification LEDs for the specified duration.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        target: Target device MAC address string
        duration_ms: Flash duration in milliseconds (default: 3000)
        timeout_sec: Response timeout in seconds

    Returns:
        True if response received, False if timeout
    """
    dst = s2mac(target)
    xid = _generate_xid()

    # Signal block data: BlockInfo (2 bytes) + SignalValue (2 bytes)
    # BlockInfo: 0x0001 = temporary signal
    # SignalValue: duration in 100ms units
    duration_units = max(1, duration_ms // 100)  # Convert to 100ms units
    block_info = bytes([0x00, 0x01])  # Temporary signal
    signal_value = duration_units.to_bytes(2, "big")
    block_data = block_info + signal_value

    block = PNDCPBlockRequest(
        DCP_OPTION_CONTROL,
        DCP_SUBOPTION_CONTROL_SIGNAL,
        len(block_data),
        payload=block_data,
    )

    dcp = PNDCPHeader(
        DCP_GET_SET_FRAME_ID,
        PNDCPHeader.SET,
        PNDCPHeader.REQUEST,
        xid,
        0,
        len(block_data) + 4,  # block header (4) + data
        payload=block,
    )
    eth = EthernetHeader(dst, src, PROFINET_ETHERTYPE, payload=dcp)

    sock.send(bytes(eth))
    logger.debug(f"Sent DCP Signal request to {target} (duration={duration_ms}ms)")

    # Wait for and validate response
    try:
        block_error = _recv_set_response(sock, src, timeout_sec)
        if block_error != DCP_BLOCK_ERROR_OK:
            error_name = DCP_BLOCK_ERROR_NAMES.get(
                block_error, f"Unknown error (0x{block_error:02X})"
            )
            raise DCPError(f"DCP Signal failed: {error_name}")
        return True
    except TimeoutError:
        logger.warning(f"No response from {target} for signal command")
        return False


def reset_to_factory(
    sock: socket,
    src: bytes,
    target: str,
    mode: int = RESET_MODE_COMMUNICATION,
    timeout_sec: int = 5,
) -> bool:
    """Send DCP Reset to Factory command.

    WARNING: This will reset device configuration! Use with caution.

    Args:
        sock: Raw Ethernet socket
        src: Source MAC address (6 bytes)
        target: Target device MAC address string
        mode: Reset mode bitmask (default: RESET_MODE_COMMUNICATION)
            - RESET_MODE_COMMUNICATION (0x0002): Reset comm params (mandatory)
            - RESET_MODE_APPLICATION (0x0004): Reset application data
            - RESET_MODE_ENGINEERING (0x0008): Reset engineering data
            - RESET_MODE_ALL_DATA (0x0010): Reset all data
            - RESET_MODE_DEVICE (0x0020): Reset device
            - RESET_MODE_FACTORY (0x0040): Reset to factory image
        timeout_sec: Response timeout in seconds

    Returns:
        True if response received, False if timeout
    """
    dst = s2mac(target)
    xid = _generate_xid()

    # Reset block data: BlockQualifier (2 bytes) with reset mode
    block_qualifier = mode.to_bytes(2, "big")

    block = PNDCPBlockRequest(
        DCP_OPTION_CONTROL,
        DCP_SUBOPTION_CONTROL_RESET_TO_FACTORY,
        len(block_qualifier),
        payload=block_qualifier,
    )

    dcp = PNDCPHeader(
        DCP_GET_SET_FRAME_ID,
        PNDCPHeader.SET,
        PNDCPHeader.REQUEST,
        xid,
        0,
        len(block_qualifier) + 4,  # block header (4) + data
        payload=block,
    )
    eth = EthernetHeader(dst, src, PROFINET_ETHERTYPE, payload=dcp)

    sock.send(bytes(eth))
    logger.debug(f"Sent DCP Reset to Factory request to {target} (mode=0x{mode:04X})")

    # Wait for and validate response
    try:
        block_error = _recv_set_response(sock, src, timeout_sec)
        if block_error != DCP_BLOCK_ERROR_OK:
            error_name = DCP_BLOCK_ERROR_NAMES.get(
                block_error, f"Unknown error (0x{block_error:02X})"
            )
            raise DCPError(f"DCP Reset to Factory failed: {error_name}")
        # Device needs time to reset
        time.sleep(2)
        return True
    except TimeoutError:
        logger.warning(f"No response from {target} for reset command")
        return False
