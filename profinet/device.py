"""
PROFINET High-Level Device API.

Provides a user-friendly interface for PROFINET device operations:
- Device discovery by name or IP
- Read/write operations
- I&M record access
- Alarm handling
- Configuration validation

Example:
    >>> from profinet import ProfinetDevice
    >>> with ProfinetDevice.discover("my-device", "eth0") as device:
    ...     info = device.get_info()
    ...     print(f"Device: {info.name}, Order: {info.im0.order_id}")
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import construct as cs

from . import dcp, indices
from .alarm_listener import AlarmEndpoint, AlarmListener
from .alarms import AlarmNotification, parse_alarm_notification
from .blocks import (
    ModuleDiffBlock,
    PDRealData,
    SlotInfo,
    WriteMultipleResult,
)
from .diagnosis import DiagnosisData
from .exceptions import (
    DCPDeviceNotFoundError,
    PNIOError,
    RPCConnectionError,
    RPCError,
)
from .protocol import (
    PNInM0,
    PNInM1,
    PNInM2,
    PNInM3,
    PNInM4,
    PNInM5,
)
from .rpc import (
    RPCCon,
    epm_lookup,
    get_station_info,
)
from .util import ethernet_socket, get_mac

logger = logging.getLogger(__name__)

# =============================================================================
# Construct Struct Definitions
# =============================================================================

# Block header for I&M write operations (type + length + version)
_InMBlockHeaderStruct = cs.Struct(
    "block_type" / cs.Int16ub,
    "block_length" / cs.Int16ub,
    "version_high" / cs.Int8ub,
    "version_low" / cs.Int8ub,
)


# =============================================================================
# Module-level convenience functions
# =============================================================================


def _parse_mac(mac_str: str) -> Optional[bytes]:
    """Parse MAC address string to bytes, return None if invalid."""
    try:
        mac_str = mac_str.lower().replace("-", ":").replace(".", ":")
        parts = mac_str.split(":")
        if len(parts) == 6:
            return bytes(int(p, 16) for p in parts)
    except (ValueError, AttributeError):
        pass
    return None


def _is_mac_address(identifier: str) -> bool:
    """Check if string looks like a MAC address."""
    return _parse_mac(identifier) is not None


class scan:
    """Scan network for PROFINET devices.

    Iterator that yields ProfinetDevice instances for each device found.

    Args:
        interface: Network interface name (default: "eth0")
        timeout: Discovery timeout in seconds

    Raises:
        PermissionDeniedError: If no root/CAP_NET_RAW

    Example:
        >>> from profinet import scan
        >>> for device in scan("eth0"):
        ...     print(f"{device.name} - {device.ip}")

        >>> # Or as list
        >>> devices = list(scan("eth0"))
    """

    def __init__(self, interface: str = "eth0", timeout: float = 3.0):
        self.interface = interface
        self.timeout = timeout
        self._devices: Optional[List[ProfinetDevice]] = None

    def _discover(self) -> List[ProfinetDevice]:
        """Perform DCP discovery."""
        from .dcp import read_response, send_discover

        sock = ethernet_socket(self.interface)
        src_mac = get_mac(self.interface)

        try:
            send_discover(sock, src_mac)
            responses = read_response(sock, src_mac, timeout_sec=int(self.timeout))

            devices = []
            for mac, blocks in responses.items():
                info = dcp.DCPDeviceDescription(mac, blocks)
                devices.append(ProfinetDevice(info, self.interface, src_mac, timeout=5.0))

            return devices
        finally:
            sock.close()

    def __iter__(self):
        """Iterate over discovered devices."""
        if self._devices is None:
            self._devices = self._discover()
        return iter(self._devices)

    def __len__(self):
        """Number of devices found."""
        if self._devices is None:
            self._devices = self._discover()
        return len(self._devices)

    def __getitem__(self, index):
        """Get device by index."""
        if self._devices is None:
            self._devices = self._discover()
        return self._devices[index]


def scan_dict(interface: str = "eth0", timeout: float = 3.0) -> Dict[str, DeviceInfo]:
    """Scan network and return device info dictionary.

    Args:
        interface: Network interface name
        timeout: Discovery timeout in seconds

    Returns:
        Dict mapping device name to DeviceInfo

    Example:
        >>> from profinet import scan_dict
        >>> devices = scan_dict()
        >>> print(devices["my-device"].ip)
    """
    result = {}
    for dev in scan(interface, timeout):
        info = dev._info
        result[dev.name] = DeviceInfo(
            name=dev.name,
            ip=dev.ip,
            mac=dev.mac,
            vendor_id=info.vendor_id,
            device_id=info.device_id,
            device_type=info.device_type,
            netmask=info.netmask,
            gateway=info.gateway,
            device_roles=info.device_roles,
            vendor_name=info.vendor_name,
        )
    return result


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class WriteItem:
    """Single write operation for write_multiple()."""

    slot: int
    subslot: int
    index: int
    data: bytes
    api: int = 0


@dataclass
class DeviceInfo:
    """Complete device information summary.

    Combines DCP discovery info with I&M0 identification data.
    """

    # From DCP
    name: str = ""
    ip: str = ""
    mac: str = ""
    vendor_id: int = 0
    device_id: int = 0
    device_type: str = ""
    netmask: str = ""
    gateway: str = ""
    device_roles: Optional[List[str]] = None
    vendor_name: str = ""

    # From I&M0 (optional)
    im0: Optional[PNInM0] = None

    # From PDRealData (optional)
    topology: Optional[PDRealData] = None

    # From EPM (optional)
    annotation: str = ""  # Device model from EPM

    @property
    def serial_number(self) -> str:
        """Serial number from I&M0 if available."""
        if self.im0:
            sn = self.im0.im_serial_number
            if isinstance(sn, bytes):
                return sn.decode("latin-1").strip()
            return str(sn).strip()
        return ""

    @property
    def order_id(self) -> str:
        """Order ID from I&M0 if available."""
        if self.im0:
            oid = self.im0.order_id
            if isinstance(oid, bytes):
                return oid.decode("latin-1").strip()
            return str(oid).strip()
        return ""

    @property
    def hardware_revision(self) -> int:
        """Hardware revision from I&M0 if available."""
        if self.im0:
            return self.im0.im_hardware_revision
        return 0

    @property
    def software_revision(self) -> str:
        """Software revision string from I&M0 if available."""
        if self.im0:
            prefix = chr(self.im0.sw_revision_prefix) if self.im0.sw_revision_prefix else ""
            return f"{prefix}{self.im0.im_sw_revision_functional_enhancement}.{self.im0.im_sw_revision_bug_fix}.{self.im0.im_sw_revision_internal_change}"
        return ""


# =============================================================================
# ProfinetDevice Class
# =============================================================================


class ProfinetDevice:
    """High-level PROFINET device interface.

    Provides a user-friendly API for common PROFINET operations:
    - Device discovery (by name or IP)
    - Read/write operations with automatic connection management
    - I&M record access with type-safe classes
    - Atomic multiple writes
    - Alarm reading
    - Configuration validation via ModuleDiffBlock

    The device manages its own connection lifecycle and can be used
    as a context manager for automatic cleanup.

    Example:
        >>> # Discover device by name
        >>> with ProfinetDevice.discover("my-device", "eth0") as device:
        ...     im0 = device.read_im0()
        ...     print(f"Order: {im0.order_id}")

        >>> # Connect by IP address
        >>> with ProfinetDevice.from_ip("192.168.1.100", "eth0") as device:
        ...     device.write_im1(tag_function="Pump Control", tag_location="Building A")
    """

    def __init__(
        self,
        info: dcp.DCPDeviceDescription,
        interface: str,
        src_mac: bytes,
        timeout: float = 5.0,
    ):
        """Initialize device wrapper.

        Use discover() or from_ip() factory methods instead of calling
        this constructor directly.

        Args:
            info: DCP device description from discovery
            interface: Network interface name
            src_mac: Source MAC address (6 bytes)
            timeout: RPC timeout in seconds
        """
        self._info = info
        self._interface = interface
        self._src_mac = src_mac
        self._timeout = timeout
        self._rpc: Optional[RPCCon] = None
        self._connected = False

        # Alarm listener state
        self._alarm_listener: Optional[AlarmListener] = None
        self._alarm_callbacks: List[Callable[[AlarmNotification], None]] = []

    @classmethod
    def discover(
        cls,
        identifier: str,
        interface: str,
        timeout: float = 10.0,
    ) -> ProfinetDevice:
        """Discover device by station name or MAC address.

        Args:
            identifier: PROFINET station name OR MAC address
                       (e.g., "my-device" or "00:0c:29:ab:cd:ef")
            interface: Network interface name (e.g., "eth0")
            timeout: Discovery timeout in seconds

        Returns:
            ProfinetDevice instance (not yet connected)

        Raises:
            DCPDeviceNotFoundError: If device not found
            PermissionDeniedError: If insufficient permissions

        Example:
            >>> # By name
            >>> dev = ProfinetDevice.discover("my-device", "eth0")
            >>> # By MAC
            >>> dev = ProfinetDevice.discover("00:0c:29:ab:cd:ef", "eth0")
        """
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)

        try:
            # Check if identifier is a MAC address
            target_mac = _parse_mac(identifier)

            if target_mac:
                # Discovery by MAC address
                from .dcp import read_response, send_discover

                send_discover(sock, src_mac)
                responses = read_response(sock, src_mac, timeout_sec=int(timeout))

                for mac, blocks in responses.items():
                    if mac == target_mac:
                        info = dcp.DCPDeviceDescription(mac, blocks)
                        return cls(info, interface, src_mac, timeout=timeout)

                raise DCPDeviceNotFoundError(f"Device with MAC '{identifier}' not found")
            else:
                # Discovery by name
                info = get_station_info(sock, src_mac, identifier, timeout_sec=int(timeout))
                return cls(info, interface, src_mac, timeout=timeout)
        finally:
            sock.close()

    @classmethod
    def from_ip(
        cls,
        ip: str,
        interface: str,
        timeout: float = 10.0,
    ) -> ProfinetDevice:
        """Connect to device by IP address.

        Performs DCP discovery filtered by IP address.

        Args:
            ip: Device IP address
            interface: Network interface name
            timeout: Discovery timeout in seconds

        Returns:
            ProfinetDevice instance (not yet connected)

        Raises:
            DCPDeviceNotFoundError: If device not found at IP
            PermissionDeniedError: If insufficient permissions
        """
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)

        try:
            # Discover all devices, filter by IP
            from .dcp import read_response, send_discover

            send_discover(sock, src_mac)
            responses = read_response(sock, src_mac, timeout_sec=int(timeout))

            for mac, blocks in responses.items():
                device = dcp.DCPDeviceDescription(mac, blocks)
                if device.ip == ip:
                    return cls(device, interface, src_mac, timeout=timeout)

            raise DCPDeviceNotFoundError(f"No device found at IP {ip}")
        finally:
            sock.close()

    @classmethod
    def from_dcp_info(
        cls,
        info: dcp.DCPDeviceDescription,
        interface: str,
        timeout: float = 5.0,
    ) -> ProfinetDevice:
        """Create device from existing DCP info.

        Useful when you have already performed DCP discovery.

        Args:
            info: DCPDeviceDescription from prior discovery
            interface: Network interface name
            timeout: RPC timeout in seconds

        Returns:
            ProfinetDevice instance
        """
        src_mac = get_mac(interface)
        return cls(info, interface, src_mac, timeout=timeout)

    # =========================================================================
    # Connection Management
    # =========================================================================

    def connect(self) -> None:
        """Establish AR (Application Relationship) with device.

        This is called automatically when needed, but can be called
        explicitly for early connection establishment.

        Raises:
            RPCConnectionError: If connection fails
        """
        if self._connected and self._rpc:
            return

        self._rpc = RPCCon(self._info, timeout=self._timeout)
        try:
            self._rpc.connect(self._src_mac)
            self._connected = True
            logger.info(f"Connected to {self._info.name} ({self._info.ip})")
        except RPCError as e:
            self._rpc.close()
            self._rpc = None
            raise RPCConnectionError(f"Failed to connect to {self._info.name}: {e}") from e

    def disconnect(self) -> None:
        """Gracefully disconnect from device.

        Sends Release request to properly terminate the AR.
        """
        if self._rpc:
            self._rpc.disconnect()
            self._connected = False
            logger.debug(f"Disconnected from {self._info.name}")

    def close(self) -> None:
        """Close device connection and release resources."""
        # Stop alarm listener if running
        if self._alarm_listener:
            self._alarm_listener.stop()
            self._alarm_listener = None

        if self._rpc:
            self._rpc.close()
            self._rpc = None
            self._connected = False
            logger.debug(f"Closed connection to {self._info.name}")

    def __enter__(self) -> ProfinetDevice:
        """Context manager entry - establishes connection."""
        self.connect()
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit - closes connection."""
        self.close()

    def _ensure_connected(self) -> RPCCon:
        """Ensure connected and return RPC instance."""
        if not self._connected or not self._rpc:
            self.connect()
        assert self._rpc is not None
        return self._rpc

    # =========================================================================
    # Device Info
    # =========================================================================

    @property
    def name(self) -> str:
        """Device station name."""
        return self._info.name

    @property
    def ip(self) -> str:
        """Device IP address."""
        return self._info.ip

    @property
    def mac(self) -> str:
        """Device MAC address as string."""
        if isinstance(self._info.mac, str):
            return self._info.mac
        return ":".join(f"{b:02x}" for b in self._info.mac)

    def get_info(self, include_topology: bool = False) -> DeviceInfo:
        """Get complete device information.

        Combines DCP discovery data with I&M0 identification
        and optionally topology information.

        Args:
            include_topology: If True, also read PDRealData

        Returns:
            DeviceInfo with all available information
        """
        info = DeviceInfo(
            name=self._info.name,
            ip=self._info.ip,
            mac=self.mac,
            vendor_id=self._info.vendor_id,
            device_id=self._info.device_id,
            device_type=self._info.device_type,
            netmask=self._info.netmask,
            gateway=self._info.gateway,
            device_roles=self._info.device_roles,
            vendor_name=self._info.vendor_name,
        )

        # Try to get I&M0
        rpc = self._ensure_connected()
        try:
            info.im0 = rpc.read_im0()
        except (RPCError, PNIOError) as e:
            logger.debug(f"Failed to read I&M0: {e}")

        # Try EPM lookup for annotation
        try:
            endpoints = epm_lookup(self._info.ip)
            for ep in endpoints:
                if ep.annotation:
                    info.annotation = ep.annotation
                    break
        except Exception as e:
            logger.debug(f"EPM lookup failed: {e}")

        # Optionally get topology
        if include_topology:
            try:
                info.topology = rpc.read_pd_real_data()
            except (RPCError, PNIOError) as e:
                logger.debug(f"Failed to read topology: {e}")

        return info

    # =========================================================================
    # Read/Write Operations
    # =========================================================================

    def read(
        self,
        slot: int,
        subslot: int,
        index: int,
        api: int = 0,
    ) -> bytes:
        """Read record from device.

        Args:
            slot: Slot number
            subslot: Subslot number
            index: Record index
            api: API number (default: 0)

        Returns:
            Raw record data (without block header)

        Raises:
            RPCError: If read fails
            PNIOError: If device returns PNIO error
        """
        rpc = self._ensure_connected()
        iod = rpc.read(api=api, slot=slot, subslot=subslot, idx=index)
        return iod.payload

    def write(
        self,
        slot: int,
        subslot: int,
        index: int,
        data: bytes,
        api: int = 0,
    ) -> None:
        """Write record to device.

        Args:
            slot: Slot number
            subslot: Subslot number
            index: Record index
            data: Data to write
            api: API number (default: 0)

        Raises:
            RPCError: If write fails
            PNIOError: If device returns PNIO error
        """
        rpc = self._ensure_connected()
        rpc.write(api=api, slot=slot, subslot=subslot, idx=index, data=data)

    def write_multiple(
        self,
        writes: List[WriteItem],
    ) -> List[WriteMultipleResult]:
        """Write multiple records atomically.

        All writes are sent in a single request and processed atomically.
        More efficient than multiple individual writes.

        Args:
            writes: List of WriteItem objects

        Returns:
            List of WriteMultipleResult, one per write

        Raises:
            RPCError: If operation fails

        Example:
            >>> results = device.write_multiple([
            ...     WriteItem(slot=0, subslot=1, index=0xAFF1, data=im1_data),
            ...     WriteItem(slot=0, subslot=1, index=0xAFF2, data=im2_data),
            ... ])
            >>> all_ok = all(r.success for r in results)
        """
        rpc = self._ensure_connected()
        write_tuples = [(w.slot, w.subslot, w.index, w.data, w.api) for w in writes]
        return rpc.write_multiple(write_tuples)

    # =========================================================================
    # I&M Record Convenience Methods
    # =========================================================================

    def read_im0(self, slot: int = 0, subslot: int = 1) -> PNInM0:
        """Read I&M0 identification data.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            PNInM0 with device identification
        """
        rpc = self._ensure_connected()
        return rpc.read_im0(slot, subslot)

    def read_im1(self, slot: int = 0, subslot: int = 1) -> PNInM1:
        """Read I&M1 tag function/location data.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            PNInM1 with tag function and location
        """
        rpc = self._ensure_connected()
        return rpc.read_im1(slot, subslot)

    def read_im2(self, slot: int = 0, subslot: int = 1) -> PNInM2:
        """Read I&M2 installation date.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            PNInM2 with installation date
        """
        rpc = self._ensure_connected()
        return rpc.read_im2(slot, subslot)

    def read_im3(self, slot: int = 0, subslot: int = 1) -> PNInM3:
        """Read I&M3 descriptor data.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            PNInM3 with descriptor
        """
        rpc = self._ensure_connected()
        return rpc.read_im3(slot, subslot)

    def read_im4(self, slot: int = 0, subslot: int = 1) -> PNInM4:
        """Read I&M4 PROFIsafe signature.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            PNInM4 with signature
        """
        rpc = self._ensure_connected()
        return rpc.read_im4(slot, subslot)

    def read_im5(self, slot: int = 0, subslot: int = 1) -> PNInM5:
        """Read I&M5 annotation data.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            PNInM5 with annotation
        """
        rpc = self._ensure_connected()
        return rpc.read_im5(slot, subslot)

    def read_all_im(self, slot: int = 0, subslot: int = 1) -> Dict[str, Any]:
        """Read all available I&M records.

        Attempts to read I&M0-5 and returns only those supported.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Returns:
            Dictionary with available I&M records
        """
        rpc = self._ensure_connected()
        return rpc.read_all_im(slot, subslot)

    def write_im1(
        self,
        tag_function: str,
        tag_location: str,
        slot: int = 0,
        subslot: int = 1,
    ) -> None:
        """Write I&M1 tag function and location.

        Args:
            tag_function: Function tag (max 32 chars)
            tag_location: Location tag (max 22 chars)
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Raises:
            ValueError: If strings exceed maximum length
            RPCError: If write fails
        """
        if len(tag_function) > 32:
            raise ValueError("tag_function exceeds 32 character limit")
        if len(tag_location) > 22:
            raise ValueError("tag_location exceeds 22 character limit")

        # Build I&M1 data: BlockHeader(6) + Padding(2) + TagFunction(32) + TagLocation(22)
        # Total: 62 bytes
        header = _InMBlockHeaderStruct.build(
            {
                "block_type": 0x0021,
                "block_length": 58,
                "version_high": 0x01,
                "version_low": 0x00,
            }
        )
        padding = b"\x00\x00"
        func_bytes = tag_function.encode("latin-1")[:32].ljust(32, b"\x20")
        loc_bytes = tag_location.encode("latin-1")[:22].ljust(22, b"\x20")

        data = header + padding + func_bytes + loc_bytes
        self.write(slot, subslot, indices.IM1, data)

    def write_im2(
        self,
        date: str,
        slot: int = 0,
        subslot: int = 1,
    ) -> None:
        """Write I&M2 installation date.

        Args:
            date: Date string (format: "YYYY-MM-DD HH:MM", max 16 chars)
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Raises:
            ValueError: If date exceeds maximum length
            RPCError: If write fails
        """
        if len(date) > 16:
            raise ValueError("date exceeds 16 character limit")

        # Build I&M2 data: BlockHeader(6) + Padding(2) + InstallationDate(16)
        header = _InMBlockHeaderStruct.build(
            {
                "block_type": 0x0022,
                "block_length": 20,
                "version_high": 0x01,
                "version_low": 0x00,
            }
        )
        padding = b"\x00\x00"
        date_bytes = date.encode("latin-1")[:16].ljust(16, b"\x20")

        data = header + padding + date_bytes
        self.write(slot, subslot, indices.IM2, data)

    def write_im3(
        self,
        descriptor: str,
        slot: int = 0,
        subslot: int = 1,
    ) -> None:
        """Write I&M3 descriptor.

        Args:
            descriptor: Descriptor string (max 54 chars)
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 1)

        Raises:
            ValueError: If descriptor exceeds maximum length
            RPCError: If write fails
        """
        if len(descriptor) > 54:
            raise ValueError("descriptor exceeds 54 character limit")

        # Build I&M3 data: BlockHeader(6) + Padding(2) + Descriptor(54)
        header = _InMBlockHeaderStruct.build(
            {
                "block_type": 0x0023,
                "block_length": 58,
                "version_high": 0x01,
                "version_low": 0x00,
            }
        )
        padding = b"\x00\x00"
        desc_bytes = descriptor.encode("latin-1")[:54].ljust(54, b"\x20")

        data = header + padding + desc_bytes
        self.write(slot, subslot, indices.IM3, data)

    # =========================================================================
    # Configuration & Diagnosis
    # =========================================================================

    def read_module_diff(self) -> ModuleDiffBlock:
        """Read ModuleDiffBlock to check configuration status.

        Compares expected vs. real module/submodule configuration.

        Returns:
            ModuleDiffBlock with per-module state info

        Example:
            >>> diff = device.read_module_diff()
            >>> if diff.all_ok:
            ...     print("Configuration matches!")
            >>> else:
            ...     for slot, subslot, state in diff.get_mismatches():
            ...         print(f"Mismatch: slot={slot} subslot={subslot}: {state}")
        """
        rpc = self._ensure_connected()
        return rpc.read_module_diff()

    def read_diagnosis(
        self,
        slot: int = 0,
        subslot: int = 0,
        index: int = 0xF000,
    ) -> DiagnosisData:
        """Read diagnosis data from device.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 0)
            index: Diagnosis index (default: 0xF000 for all)

        Returns:
            DiagnosisData with parsed diagnosis entries
        """
        rpc = self._ensure_connected()
        return rpc.read_diagnosis(slot, subslot, index)

    def read_all_diagnosis(self) -> Dict[int, DiagnosisData]:
        """Read diagnosis from all standard indices.

        Returns:
            Dictionary mapping index to DiagnosisData
        """
        rpc = self._ensure_connected()
        return rpc.read_all_diagnosis()

    def discover_slots(self) -> List[SlotInfo]:
        """Discover all slots/subslots from device.

        Reads RealIdentificationData (0xF000) for complete
        logical structure.

        Returns:
            List of SlotInfo for each slot/subslot
        """
        rpc = self._ensure_connected()
        return rpc.discover_slots()

    def read_topology(self) -> PDRealData:
        """Read physical topology (PDRealData).

        Returns:
            PDRealData with interface and port information
        """
        rpc = self._ensure_connected()
        return rpc.read_pd_real_data()

    # =========================================================================
    # Alarm Reading
    # =========================================================================

    def read_alarm(
        self,
        slot: int = 0,
        subslot: int = 0,
        index: int = 0x800C,
    ) -> Optional[AlarmNotification]:
        """Read alarm data from device.

        Attempts to read alarm notification data at the specified
        location. Returns None if no alarm is present.

        Args:
            slot: Slot number (default: 0)
            subslot: Subslot number (default: 0)
            index: Alarm record index (default: 0x800C for subslot alarm)

        Returns:
            AlarmNotification if alarm present, None otherwise
        """
        try:
            data = self.read(slot, subslot, index)
            if len(data) >= 28:  # Minimum alarm notification size
                return parse_alarm_notification(data)
            return None
        except (RPCError, PNIOError):
            return None

    def on_alarm(
        self,
        callback: Callable[[AlarmNotification], None],
    ) -> None:
        """Register callback for alarm notifications.

        Callbacks are invoked from the alarm listener thread for each
        received alarm notification. Can be called before or after
        starting the listener.

        Args:
            callback: Function that receives AlarmNotification

        Example:
            >>> def handle_alarm(alarm):
            ...     print(f"Alarm: {alarm.alarm_type_name} at {alarm.location}")
            >>> device.on_alarm(handle_alarm)
            >>> device.start_alarm_listener()
        """
        self._alarm_callbacks.append(callback)
        if self._alarm_listener:
            self._alarm_listener.add_callback(callback)

    def start_alarm_listener(self) -> None:
        """Start background alarm listener.

        Requires an established connection with AlarmCR enabled.
        The listener runs in a background thread, receiving alarm
        notifications and invoking registered callbacks.

        Raises:
            RuntimeError: If not connected or AlarmCR not established

        Example:
            >>> with device:
            ...     device.on_alarm(lambda a: print(a.alarm_type_name))
            ...     device.start_alarm_listener()
            ...     # Wait for alarms...
            ...     import time
            ...     time.sleep(60)
        """
        if not self._connected or not self._rpc:
            raise RuntimeError("Must be connected first")

        if not self._rpc._alarm_cr_enabled:
            raise RuntimeError("AlarmCR not established. Reconnect with with_alarm_cr=True")

        # Create endpoint from RPC state
        device_mac = self._info.mac
        if isinstance(device_mac, str):
            device_mac = bytes.fromhex(device_mac.replace(":", ""))

        endpoint = AlarmEndpoint(
            interface=self._interface,
            controller_ref=self._rpc._alarm_ref,
            device_ref=self._rpc._device_alarm_ref,
            device_mac=device_mac,
            transport=0,  # Layer 2
        )

        self._alarm_listener = AlarmListener(endpoint, self._src_mac)

        # Add existing callbacks
        for callback in self._alarm_callbacks:
            self._alarm_listener.add_callback(callback)

        self._alarm_listener.start()
        logger.info(f"Alarm listener started for {self._info.name}")

    def stop_alarm_listener(self) -> None:
        """Stop background alarm listener.

        Safe to call even if listener is not running.
        """
        if self._alarm_listener:
            self._alarm_listener.stop()
            self._alarm_listener = None
            logger.info(f"Alarm listener stopped for {self._info.name}")

    @property
    def alarm_listener_running(self) -> bool:
        """True if alarm listener is currently running."""
        return self._alarm_listener is not None and self._alarm_listener.is_running

    # =========================================================================
    # Cyclic IO
    # =========================================================================

    def start_cyclic(
        self,
        iocr_setup: Any,
        max_consecutive_timeouts: int = 3,
    ) -> Any:
        """Start cyclic IO exchange with device.

        Handles the full cyclic IO lifecycle:
        1. Connect with IOCARSingle + IOCR + AlarmCR
        2. PrmEnd (end parameter phase)
        3. ApplicationReady (wait for device CControl)
        4. Build IOCRConfigs from IOCRSetup
        5. Create and start CyclicController

        Args:
            iocr_setup: IOCRSetup with slots, timing, etc.
            max_consecutive_timeouts: Watchdog timeouts before FAULT
                (0 = never enter FAULT)

        Returns:
            CyclicController instance (already started)

        Raises:
            RPCConnectionError: If connection fails
            RPCError: If PrmEnd or ApplicationReady fails
            RuntimeError: If cyclic IO not established

        Example:
            >>> from profinet import IOCRSetup, IOSlot
            >>> setup = IOCRSetup(slots=[
            ...     IOSlot(slot=1, subslot=1, input_length=4, output_length=4,
            ...            module_ident=0x01, submodule_ident=0x01),
            ... ])
            >>> with ProfinetDevice.discover("dev", "eth0") as device:
            ...     cyclic = device.start_cyclic(setup)
            ...     cyclic.set_output_data(1, 1, b'\\x01\\x02\\x03\\x04')
            ...     data = cyclic.get_input_data(1, 1)
            ...     cyclic.stop()
        """
        from .cyclic import CyclicController
        from .rt import build_iocr_configs

        # 1. Connect with IOCR
        rpc = self._ensure_connected()
        result = rpc.connect(
            src_mac=self._src_mac,
            with_alarm_cr=True,
            iocr_setup=iocr_setup,
        )
        if not result or not result.has_cyclic:
            raise RuntimeError("Cyclic IO not established by device")

        # 2. PrmEnd
        rpc.prm_end()

        # 3. ApplicationReady
        rpc.application_ready(timeout=30.0)

        # 4. Build IOCRConfigs (uses shared helper for proper IOCS handling)
        dst_mac = self._info.mac
        if isinstance(dst_mac, str):
            dst_mac = bytes.fromhex(dst_mac.replace(":", ""))

        input_iocr, output_iocr = build_iocr_configs(
            slots=iocr_setup.slots,
            input_frame_id=result.input_frame_id,
            output_frame_id=result.output_frame_id,
            send_clock_factor=iocr_setup.send_clock_factor,
            reduction_ratio=iocr_setup.reduction_ratio,
            watchdog_factor=iocr_setup.watchdog_factor,
        )

        # 5. Create and start CyclicController
        cyclic = CyclicController(
            interface=self._interface,
            src_mac=self._src_mac,
            dst_mac=dst_mac,
            input_iocr=input_iocr,
            output_iocr=output_iocr,
            max_consecutive_timeouts=max_consecutive_timeouts,
        )
        cyclic.start()

        return cyclic

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def enumerate_indices(
        self,
        slot: int = 0,
        subslot: int = 1,
    ) -> Dict[int, Dict[str, Any]]:
        """Enumerate available record indices.

        Probes common indices and reports which are readable.

        Args:
            slot: Slot number to probe
            subslot: Subslot number to probe

        Returns:
            Dictionary mapping index to result info
        """
        rpc = self._ensure_connected()
        return rpc.enumerate_indices(slot, subslot)

    def __repr__(self) -> str:
        status = "connected" if self._connected else "disconnected"
        return f"ProfinetDevice({self._info.name!r}, {self._info.ip}, {status})"
