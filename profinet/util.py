"""
Utility functions for PROFINET packet handling.

Provides:
- MAC/IP address conversion utilities
- Socket creation helpers (cross-platform: Linux AF_PACKET, Windows Npcap)
- Packet structure factory (make_packet)
- Timeout context manager

"""

from __future__ import annotations

import ipaddress
import logging
import re
import sys
import time
from collections import OrderedDict, namedtuple
from collections.abc import Callable
from typing import Any, Dict, List, Optional, Tuple, Type, Union

import construct as cs

from .exceptions import InvalidIPError, InvalidMACError, PermissionDeniedError, SocketError

logger = logging.getLogger(__name__)

# =============================================================================
# Constants
# =============================================================================

# Network constants
MAX_ETHERNET_FRAME = 1522
PROFINET_ETHERTYPE = 0x8892
VLAN_ETHERTYPE = 0x8100
ETH_P_ALL = 0x0003  # Receive all Ethernet protocols

# Validation patterns
MAC_PATTERN = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


# =============================================================================
# Address Conversion Utilities
# =============================================================================


def to_hex(data: bytes) -> str:
    """Convert bytes to colon-separated hex string."""
    return ":".join(f"{c:02x}" for c in data)


def s2mac(mac_str: str) -> bytes:
    """Convert MAC address string to bytes.

    Args:
        mac_str: MAC address in format "aa:bb:cc:dd:ee:ff"

    Returns:
        6-byte MAC address

    Raises:
        InvalidMACError: If MAC address format is invalid
    """
    if not mac_str:
        raise InvalidMACError("MAC address cannot be empty")

    if not MAC_PATTERN.match(mac_str):
        raise InvalidMACError(
            f"Invalid MAC address format: {mac_str!r}. Expected format: aa:bb:cc:dd:ee:ff"
        )

    try:
        result = bytes(int(num, 16) for num in mac_str.split(":"))
        if len(result) != 6:
            raise InvalidMACError(f"MAC address must be 6 bytes, got {len(result)}")
        return result
    except ValueError as e:
        raise InvalidMACError(f"Invalid MAC address: {mac_str!r}") from e


def mac2s(mac_bytes: bytes) -> str:
    """Convert MAC address bytes to string.

    Args:
        mac_bytes: 6-byte MAC address

    Returns:
        MAC address in format "aa:bb:cc:dd:ee:ff"

    Raises:
        InvalidMACError: If input is not 6 bytes
    """
    if len(mac_bytes) != 6:
        raise InvalidMACError(f"MAC address must be 6 bytes, got {len(mac_bytes)}")
    return ":".join(f"{num:02x}" for num in mac_bytes)


def s2ip(ip_bytes: bytes) -> str:
    """Convert IP address bytes to dotted decimal string.

    Args:
        ip_bytes: 4-byte IP address

    Returns:
        IP address in format "192.168.1.1"

    Raises:
        InvalidIPError: If input is not 4 bytes
    """
    if len(ip_bytes) < 4:
        raise InvalidIPError(f"IP address must be at least 4 bytes, got {len(ip_bytes)}")
    return ".".join(str(o) for o in ip_bytes[:4])


def ip2s(ip_str: str) -> bytes:
    """Convert dotted decimal IP string to bytes.

    Args:
        ip_str: IP address in format "192.168.1.1"

    Returns:
        4-byte IP address

    Raises:
        InvalidIPError: If IP address format is invalid
    """
    if not ip_str:
        raise InvalidIPError("IP address cannot be empty")

    try:
        # Use ipaddress module for robust validation
        addr = ipaddress.IPv4Address(ip_str)
        return addr.packed
    except ipaddress.AddressValueError as e:
        raise InvalidIPError(f"Invalid IP address: {ip_str!r}") from e


def decode_bytes(data: bytes) -> str:
    """Decode bytes to string, stripping null terminators."""
    return data.rstrip(b"\x00").decode("utf-8", errors="replace")


# =============================================================================
# Socket Utilities — Platform Abstraction
# =============================================================================

if sys.platform == "win32":
    # =========================================================================
    # Windows: Npcap/WinPcap via ctypes (wpcap.dll)
    # =========================================================================
    import ctypes
    import ctypes.wintypes

    # ---- pcap ctypes bindings -----------------------------------------------

    PCAP_ERRBUF_SIZE = 256

    class _timeval(ctypes.Structure):
        _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]

    class _pcap_pkthdr(ctypes.Structure):
        _fields_ = [
            ("ts", _timeval),
            ("caplen", ctypes.c_uint),
            ("len", ctypes.c_uint),
        ]

    class _bpf_insn(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint),
        ]

    class _bpf_program(ctypes.Structure):
        _fields_ = [
            ("bf_len", ctypes.c_uint),
            ("bf_insns", ctypes.POINTER(_bpf_insn)),
        ]

    class _pcap_addr(ctypes.Structure):
        pass

    class _sockaddr(ctypes.Structure):
        _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_char * 14)]

    _pcap_addr._fields_ = [
        ("next", ctypes.POINTER(_pcap_addr)),
        ("addr", ctypes.POINTER(_sockaddr)),
        ("netmask", ctypes.POINTER(_sockaddr)),
        ("broadaddr", ctypes.POINTER(_sockaddr)),
        ("dstaddr", ctypes.POINTER(_sockaddr)),
    ]

    class _pcap_if_t(ctypes.Structure):
        pass

    _pcap_if_t._fields_ = [
        ("next", ctypes.POINTER(_pcap_if_t)),
        ("name", ctypes.c_char_p),
        ("description", ctypes.c_char_p),
        ("addresses", ctypes.POINTER(_pcap_addr)),
        ("flags", ctypes.c_uint),
    ]

    # Opaque pcap_t handle
    class _pcap_t(ctypes.Structure):
        pass

    def _load_pcap_dll():
        """Load wpcap.dll (Npcap or WinPcap).

        Npcap installs to System32\\Npcap, WinPcap to System32.
        We try Npcap first (recommended), then fall back to WinPcap.
        """
        import os

        npcap_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
        # Try Npcap directory first
        if os.path.isdir(npcap_path):
            try:
                return ctypes.CDLL(os.path.join(npcap_path, "wpcap.dll"))
            except OSError:
                pass
        # Fall back to system path (WinPcap or Npcap in WinPcap-compatible mode)
        try:
            return ctypes.CDLL("wpcap.dll")
        except OSError:
            raise SocketError(
                "Npcap or WinPcap is required but not found. "
                "Install Npcap from https://npcap.com/ "
                "(enable 'WinPcap API-compatible Mode' during installation)."
            ) from None

    def _init_pcap_functions(lib):
        """Set up argtypes/restype for all pcap functions we use."""
        _pcap_t_p = ctypes.POINTER(_pcap_t)

        lib.pcap_open_live.argtypes = [
            ctypes.c_char_p,  # device
            ctypes.c_int,  # snaplen
            ctypes.c_int,  # promisc
            ctypes.c_int,  # to_ms
            ctypes.c_char_p,  # errbuf
        ]
        lib.pcap_open_live.restype = _pcap_t_p

        lib.pcap_close.argtypes = [_pcap_t_p]
        lib.pcap_close.restype = None

        lib.pcap_sendpacket.argtypes = [
            _pcap_t_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_int,
        ]
        lib.pcap_sendpacket.restype = ctypes.c_int

        lib.pcap_next_ex.argtypes = [
            _pcap_t_p,
            ctypes.POINTER(ctypes.POINTER(_pcap_pkthdr)),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
        ]
        lib.pcap_next_ex.restype = ctypes.c_int

        lib.pcap_compile.argtypes = [
            _pcap_t_p,
            ctypes.POINTER(_bpf_program),
            ctypes.c_char_p,  # filter expression
            ctypes.c_int,  # optimize
            ctypes.c_uint,  # netmask
        ]
        lib.pcap_compile.restype = ctypes.c_int

        lib.pcap_setfilter.argtypes = [_pcap_t_p, ctypes.POINTER(_bpf_program)]
        lib.pcap_setfilter.restype = ctypes.c_int

        lib.pcap_freecode.argtypes = [ctypes.POINTER(_bpf_program)]
        lib.pcap_freecode.restype = None

        lib.pcap_setnonblock.argtypes = [_pcap_t_p, ctypes.c_int, ctypes.c_char_p]
        lib.pcap_setnonblock.restype = ctypes.c_int

        lib.pcap_findalldevs.argtypes = [
            ctypes.POINTER(ctypes.POINTER(_pcap_if_t)),
            ctypes.c_char_p,
        ]
        lib.pcap_findalldevs.restype = ctypes.c_int

        lib.pcap_freealldevs.argtypes = [ctypes.POINTER(_pcap_if_t)]
        lib.pcap_freealldevs.restype = None

        lib.pcap_geterr.argtypes = [_pcap_t_p]
        lib.pcap_geterr.restype = ctypes.c_char_p

        return lib

    # Lazy-loaded singleton
    _pcap_lib = None

    def _get_pcap():
        global _pcap_lib
        if _pcap_lib is None:
            _pcap_lib = _init_pcap_functions(_load_pcap_dll())
        return _pcap_lib

    # ---- Interface name resolution ------------------------------------------

    def _pcap_list_devices() -> List[Tuple[str, str]]:
        """List all pcap devices as (name, description) pairs.

        Returns:
            List of (device_name, description) tuples.
            device_name is the NPF path, description is human-readable.
        """
        pcap = _get_pcap()
        alldevs = ctypes.POINTER(_pcap_if_t)()
        errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)

        if pcap.pcap_findalldevs(ctypes.byref(alldevs), errbuf) != 0:
            raise SocketError(f"pcap_findalldevs failed: {errbuf.value.decode()}")

        devices = []
        try:
            dev = alldevs
            while dev:
                name = (
                    dev.contents.name.decode("utf-8", errors="replace") if dev.contents.name else ""
                )
                desc = (
                    dev.contents.description.decode("utf-8", errors="replace")
                    if dev.contents.description
                    else ""
                )
                devices.append((name, desc))
                dev = dev.contents.next
        finally:
            pcap.pcap_freealldevs(alldevs)

        return devices

    def _resolve_friendly_name_to_guid(friendly_name: str) -> Optional[str]:
        """Resolve a Windows friendly interface name to its adapter GUID.

        Maps names like "Ethernet 3" to "{GUID}" by querying the Windows
        registry under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Network.

        Returns:
            The adapter GUID string (e.g., "{824533DB-...}"), or None if not found.
        """
        import winreg

        try:
            # Enumerate network adapter connections in the registry
            base = (
                r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            )
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as net_key:
                i = 0
                while True:
                    try:
                        guid = winreg.EnumKey(net_key, i)
                        i += 1
                        if not guid.startswith("{"):
                            continue
                        conn_path = f"{base}\\{guid}\\Connection"
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, conn_path) as conn_key:
                                name, _ = winreg.QueryValueEx(conn_key, "Name")
                                if name.lower() == friendly_name.lower():
                                    return guid
                        except OSError:
                            continue
                    except OSError:
                        break
        except OSError:
            pass
        return None

    def _resolve_pcap_device(interface: str) -> str:
        """Resolve a friendly interface name to the NPF device path.

        Accepts:
        - Full NPF path (returned as-is): ``\\Device\\NPF_{GUID}``
        - A GUID: ``{GUID}`` -> ``\\Device\\NPF_{GUID}``
        - Friendly/description substring match (case-insensitive)
        - Numeric index into the device list

        Args:
            interface: Interface identifier (name, GUID, description, or index)

        Returns:
            NPF device path string

        Raises:
            SocketError: If the interface cannot be resolved
        """
        # Already a full NPF path
        if interface.startswith("\\Device\\NPF_") or interface.startswith("\\\\Device\\\\NPF_"):
            return interface

        # Bare GUID
        if interface.startswith("{") and interface.endswith("}"):
            return f"\\Device\\NPF_{interface}"

        devices = _pcap_list_devices()
        if not devices:
            raise SocketError("No pcap devices found. Is Npcap installed?")

        # Try numeric index
        try:
            idx = int(interface)
            if 0 <= idx < len(devices):
                return devices[idx][0]
        except ValueError:
            pass

        # Case-insensitive substring match against name and description
        iface_lower = interface.lower()
        for name, desc in devices:
            if iface_lower in name.lower() or iface_lower in desc.lower():
                return name

        # Windows friendly name resolution (e.g., "Ethernet 3" -> NPF device)
        # Maps friendly names to adapter GUIDs via the Windows registry
        guid = _resolve_friendly_name_to_guid(interface)
        if guid:
            npf_path = f"\\Device\\NPF_{guid}"
            # Verify this device exists in pcap list
            for name, _desc in devices:
                if guid.lower() in name.lower():
                    return name
            # Device exists in registry but not in pcap -- try anyway
            return npf_path

        available = "\n".join(f"  [{i}] {name}  ({desc})" for i, (name, desc) in enumerate(devices))
        raise SocketError(
            f"Interface {interface!r} not found in pcap device list.\n"
            f"Available devices:\n{available}"
        )

    # ---- NpcapSocket wrapper ------------------------------------------------

    class NpcapSocket:
        """Raw Ethernet socket using Npcap/WinPcap on Windows.

        Provides the same send/recv/close/settimeout API as a Linux AF_PACKET
        socket so callers do not need platform-specific code.
        """

        def __init__(self, interface: str, ethertype: Optional[int] = None):
            """Open a live pcap capture on the given interface.

            Args:
                interface: Network interface (friendly name, NPF path, or index)
                ethertype: Optional EtherType to filter on. If ``None``, all
                    Ethernet frames are captured (ETH_P_ALL equivalent).

            Raises:
                SocketError: If Npcap is not installed or the device cannot be opened.
                PermissionDeniedError: If the user lacks capture privileges.
            """
            self._handle = None
            self._pcap = None
            pcap = _get_pcap()
            device = _resolve_pcap_device(interface)
            errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)

            self._handle = pcap.pcap_open_live(
                device.encode("utf-8"),
                65535,  # snaplen
                1,  # promisc
                1,  # read timeout in ms (low for responsiveness)
                errbuf,
            )
            if not self._handle:
                err_msg = errbuf.value.decode("utf-8", errors="replace")
                if "permission" in err_msg.lower() or "access" in err_msg.lower():
                    raise PermissionDeniedError(
                        f"Administrator privileges required for raw capture: {err_msg}"
                    )
                raise SocketError(f"pcap_open_live failed on {device!r}: {err_msg}")

            self._pcap = pcap
            self._timeout: Optional[float] = None
            self._interface = interface
            self._device = device

            # Apply BPF filter for ethertype
            if ethertype is not None and ethertype != ETH_P_ALL:
                self._set_filter(f"ether proto 0x{ethertype:04x}")

        def _set_filter(self, expression: str) -> None:
            """Compile and apply a BPF filter expression."""
            filt = _bpf_program()
            if (
                self._pcap.pcap_compile(self._handle, ctypes.byref(filt), expression.encode(), 1, 0)
                != 0
            ):
                err = self._pcap.pcap_geterr(self._handle)
                logger.warning(
                    f"pcap_compile failed for {expression!r}: {err.decode() if err else 'unknown'}"
                )
                return
            try:
                if self._pcap.pcap_setfilter(self._handle, ctypes.byref(filt)) != 0:
                    err = self._pcap.pcap_geterr(self._handle)
                    logger.warning(f"pcap_setfilter failed: {err.decode() if err else 'unknown'}")
            finally:
                self._pcap.pcap_freecode(ctypes.byref(filt))

        def send(self, data: bytes) -> int:
            """Send a raw Ethernet frame.

            Args:
                data: Complete Ethernet frame (including dst/src MAC and EtherType)

            Returns:
                Number of bytes sent

            Raises:
                SocketError: If the send fails
            """
            buf = (ctypes.c_ubyte * len(data))(*data)
            ret = self._pcap.pcap_sendpacket(self._handle, buf, len(data))
            if ret != 0:
                err = self._pcap.pcap_geterr(self._handle)
                raise SocketError(f"pcap_sendpacket failed: {err.decode() if err else 'unknown'}")
            return len(data)

        def recv(self, bufsize: int = MAX_ETHERNET_FRAME) -> bytes:
            """Receive a raw Ethernet frame.

            Blocks up to the configured timeout (see ``settimeout``).

            Args:
                bufsize: Maximum bytes to return (frames larger than this are truncated)

            Returns:
                Raw Ethernet frame bytes

            Raises:
                socket.timeout: If no packet is received within the timeout period
                SocketError: On capture error
            """
            header = ctypes.POINTER(_pcap_pkthdr)()
            pkt_data = ctypes.POINTER(ctypes.c_ubyte)()

            deadline = None
            if self._timeout is not None:
                deadline = time.monotonic() + self._timeout

            while True:
                ret = self._pcap.pcap_next_ex(
                    self._handle, ctypes.byref(header), ctypes.byref(pkt_data)
                )
                if ret == 1:
                    # Packet received
                    length = min(header.contents.caplen, bufsize)
                    return bytes(pkt_data[:length])
                elif ret == 0:
                    # Timeout from pcap_open_live read timeout — check deadline
                    if deadline is not None and time.monotonic() >= deadline:
                        raise TimeoutError("timed out")
                    continue
                else:
                    # ret == -1 or -2: error or EOF
                    err = self._pcap.pcap_geterr(self._handle)
                    raise SocketError(f"pcap_next_ex error: {err.decode() if err else 'unknown'}")

        def settimeout(self, timeout: Optional[float]) -> None:
            """Set the receive timeout.

            Args:
                timeout: Timeout in seconds, or ``None`` for blocking
            """
            self._timeout = timeout

        def close(self) -> None:
            """Close the pcap handle."""
            if self._handle:
                self._pcap.pcap_close(self._handle)
                self._handle = None

        def fileno(self) -> int:
            """Not supported on Windows pcap — raises OSError."""
            raise OSError("fileno() is not supported for NpcapSocket on Windows")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

        def __del__(self):
            self.close()

    # ---- MAC address via GetAdaptersAddresses (iphlpapi.dll) ----------------

    # Constants for GetAdaptersAddresses
    _AF_UNSPEC = 0
    _GAA_FLAG_INCLUDE_PREFIX = 0x0010
    _ERROR_BUFFER_OVERFLOW = 111
    _ERROR_SUCCESS = 0
    _MAX_ADAPTER_ADDRESS_LENGTH = 8

    class _SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [
            ("lpSockaddr", ctypes.c_void_p),
            ("iSockaddrLength", ctypes.c_int),
        ]

    class _IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
        pass

    _IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
        ("Length", ctypes.c_ulong),
        ("Flags", ctypes.wintypes.DWORD),
        ("Next", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
        ("Address", _SOCKET_ADDRESS),
        ("PrefixOrigin", ctypes.c_int),
        ("SuffixOrigin", ctypes.c_int),
        ("DadState", ctypes.c_int),
        ("ValidLifetime", ctypes.c_ulong),
        ("PreferredLifetime", ctypes.c_ulong),
        ("LeaseLifetime", ctypes.c_ulong),
        ("OnLinkPrefixLength", ctypes.c_ubyte),
    ]

    class _IP_ADAPTER_ADDRESSES(ctypes.Structure):
        pass

    _IP_ADAPTER_ADDRESSES._fields_ = [
        ("Length", ctypes.c_ulong),
        ("IfIndex", ctypes.wintypes.DWORD),
        ("Next", ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
        ("PhysicalAddress", ctypes.c_ubyte * _MAX_ADAPTER_ADDRESS_LENGTH),
        ("PhysicalAddressLength", ctypes.wintypes.DWORD),
        ("Flags", ctypes.wintypes.DWORD),
        ("Mtu", ctypes.wintypes.DWORD),
        ("IfType", ctypes.wintypes.DWORD),
        ("OperStatus", ctypes.c_int),
        # Many more fields follow but we only need up to PhysicalAddress
    ]

    def get_mac(ifname: str) -> bytes:
        """Get MAC address of network interface (Windows).

        Queries ``GetAdaptersAddresses`` from ``iphlpapi.dll`` and matches
        the adapter by friendly name, description, or adapter GUID.

        Args:
            ifname: Network interface name (friendly name like "Ethernet",
                adapter name like ``{GUID}``, or description substring)

        Returns:
            6-byte MAC address

        Raises:
            SocketError: If interface is not found or API call fails
        """
        if not ifname:
            raise SocketError("Interface name cannot be empty")

        iphlpapi = ctypes.windll.iphlpapi

        # First call: get required buffer size
        buf_size = ctypes.c_ulong(0)
        ret = iphlpapi.GetAdaptersAddresses(
            _AF_UNSPEC, _GAA_FLAG_INCLUDE_PREFIX, None, None, ctypes.byref(buf_size)
        )
        if ret != _ERROR_BUFFER_OVERFLOW:
            raise SocketError(f"GetAdaptersAddresses sizing failed (error {ret})")

        # Allocate buffer and retrieve data
        buf = ctypes.create_string_buffer(buf_size.value)
        adapter_p = ctypes.cast(buf, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
        ret = iphlpapi.GetAdaptersAddresses(
            _AF_UNSPEC, _GAA_FLAG_INCLUDE_PREFIX, None, adapter_p, ctypes.byref(buf_size)
        )
        if ret != _ERROR_SUCCESS:
            raise SocketError(f"GetAdaptersAddresses failed (error {ret})")

        # Walk linked list, match by name
        ifname_lower = ifname.lower()
        while adapter_p:
            a = adapter_p.contents
            friendly = a.FriendlyName or ""
            desc = a.Description or ""
            adapter_name = a.AdapterName.decode("utf-8", errors="replace") if a.AdapterName else ""

            if (
                ifname_lower == friendly.lower()
                or ifname_lower == desc.lower()
                or ifname_lower in friendly.lower()
                or ifname_lower in desc.lower()
                or ifname_lower in adapter_name.lower()
            ):
                length = a.PhysicalAddressLength
                if length >= 6:
                    return bytes(a.PhysicalAddress[:6])

            adapter_p = a.Next

        raise SocketError(f"No adapter matching {ifname!r} found via GetAdaptersAddresses")

    def ethernet_socket(interface: str, ethertype: int = None) -> NpcapSocket:
        """Create raw Ethernet socket bound to interface (Windows).

        Uses Npcap/WinPcap via ctypes for raw packet capture and injection.

        Args:
            interface: Network interface (friendly name, NPF path, GUID, or index)
            ethertype: Ethernet type to filter. If ``None``, receives all packets.

        Returns:
            NpcapSocket instance with send/recv/close/settimeout API

        Raises:
            PermissionDeniedError: If not running as Administrator
            SocketError: If Npcap is not installed or socket creation fails
        """
        if not interface:
            raise SocketError("Interface name cannot be empty")

        proto = ethertype if ethertype is not None else ETH_P_ALL
        try:
            return NpcapSocket(interface, proto)
        except PermissionDeniedError:
            raise
        except SocketError:
            raise
        except Exception as e:
            raise SocketError(f"Failed to create pcap socket on {interface!r}: {e}") from e


else:
    # =========================================================================
    # Linux: AF_PACKET (original implementation)
    # =========================================================================
    from fcntl import ioctl
    from socket import AF_INET, AF_PACKET, SOCK_DGRAM, SOCK_RAW, htons, socket

    # ioctl constants (Linux-specific)
    SIOCGIFHWADDR = 0x8927

    def get_mac(ifname: str) -> bytes:
        """Get MAC address of network interface (Linux).

        Args:
            ifname: Network interface name (e.g., "eth0")

        Returns:
            6-byte MAC address

        Raises:
            SocketError: If interface doesn't exist or ioctl fails
        """
        if not ifname:
            raise SocketError("Interface name cannot be empty")

        try:
            with socket(AF_INET, SOCK_DGRAM) as s:
                info = ioctl(
                    s.fileno(),
                    SIOCGIFHWADDR,
                    bytes(ifname[:15], "ascii").ljust(256, b"\x00"),
                )
            return info[18:24]
        except OSError as e:
            raise SocketError(f"Failed to get MAC address for {ifname!r}: {e}") from e

    def ethernet_socket(interface: str, ethertype: int = None) -> socket:
        """Create raw Ethernet socket bound to interface (Linux).

        Args:
            interface: Network interface name
            ethertype: Ethernet type to filter. If None, receives all packets
                       (needed for VLAN-tagged responses). Default: ETH_P_ALL.

        Returns:
            Bound raw socket

        Raises:
            PermissionDeniedError: If not running as root
            SocketError: If socket creation or binding fails

        Note:
            Uses ETH_P_ALL by default because some devices (e.g., Siemens S7-1200)
            respond with VLAN-tagged frames (0x8100) even to non-VLAN requests.
        """
        if not interface:
            raise SocketError("Interface name cannot be empty")

        # Default to ETH_P_ALL to capture VLAN-tagged responses
        proto = ethertype if ethertype is not None else ETH_P_ALL

        try:
            s = socket(AF_PACKET, SOCK_RAW, htons(proto))
            s.bind((interface, 0))
            return s
        except PermissionError as e:
            raise PermissionDeniedError(
                f"Root privileges required for raw socket access: {e}"
            ) from e
        except OSError as e:
            raise SocketError(f"Failed to create socket on {interface!r}: {e}") from e


def udp_socket(host: str, port: int, timeout: float = 5.0):
    """Create connected UDP socket with timeout.

    Works on all platforms (UDP does not require raw sockets).

    Args:
        host: Target hostname or IP
        port: Target port number
        timeout: Socket timeout in seconds (default: 5.0)

    Returns:
        Connected UDP socket with timeout set

    Raises:
        SocketError: If socket creation fails
    """
    import socket as _sock

    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except OSError as e:
        raise SocketError(f"Failed to create UDP socket to {host}:{port}: {e}") from e


# =============================================================================
# Timeout Context Manager
# =============================================================================


class MaxTimeout:
    """Context manager for time-limited operations.

    Usage:
        with MaxTimeout(10) as t:
            while not t.timed_out:
                # do work

    Attributes:
        seconds: Timeout duration
        remaining: Seconds remaining until timeout
    """

    def __init__(self, seconds: float):
        self.seconds = seconds
        self._die_after: float = 0

    def __enter__(self) -> MaxTimeout:
        self._die_after = time.monotonic() + self.seconds
        return self

    def __exit__(self, _exc_type: Any, _exc_val: Any, _exc_tb: Any) -> None:
        pass

    @property
    def timed_out(self) -> bool:
        """Check if timeout has elapsed."""
        return time.monotonic() > self._die_after

    @property
    def remaining(self) -> float:
        """Get remaining time in seconds."""
        return max(0, self._die_after - time.monotonic())


# Backwards compatibility alias
max_timeout = MaxTimeout


# =============================================================================
# Packet Factory (construct-backed)
# =============================================================================

# Mapping from struct format characters to construct types (big-endian)
_STRUCT_TO_CONSTRUCT: Dict[str, Any] = {
    "B": cs.Int8ub,
    "b": cs.Int8sb,
    "H": cs.Int16ub,
    "h": cs.Int16sb,
    "I": cs.Int32ub,
    "i": cs.Int32sb,
    "Q": cs.Int64ub,
    "q": cs.Int64sb,
}


def _struct_fmt_to_construct(field_name: str, fmt_char: str) -> cs.Construct:
    """Convert a single struct format character to a construct type.

    Handles both fixed-size integer types (B, H, I, etc.) and fixed-size
    byte strings (e.g., '6s', '16s').

    Args:
        field_name: Name for the construct field
        fmt_char: struct format string (e.g., 'B', 'H', '6s', '16s')

    Returns:
        construct Subconstruct for this field
    """
    if fmt_char in _STRUCT_TO_CONSTRUCT:
        return _STRUCT_TO_CONSTRUCT[fmt_char]

    # Handle fixed-size byte strings like '6s', '16s', '3s'
    if fmt_char.endswith("s"):
        byte_count = int(fmt_char[:-1])
        return cs.Bytes(byte_count)

    raise ValueError(f"Unsupported struct format: {fmt_char!r} for field {field_name!r}")


FieldSpec = Union[str, Tuple[str, "str | Callable[[bytes], str]"]]


def make_packet(
    name: str,
    fields: Tuple[Tuple[str, FieldSpec], ...],
    statics: Optional[Dict[str, Any]] = None,
    payload: bool = True,
    payload_size_field: Optional[str] = None,
    payload_offset: int = 0,
    vlf: Optional[str] = None,
    vlf_size_field: Optional[str] = None,
) -> Type:
    """Create a packet class from field definitions using construct.

    This factory creates namedtuple-based packet classes that can both
    parse binary data and serialize to bytes.  Internally the binary
    layout is described with a ``construct.Struct`` for readability,
    while the external API remains the same namedtuple interface used
    throughout the codebase.

    Args:
        name: Class name for the packet type
        fields: Tuple of (field_name, format_spec) pairs where format_spec is
                either a struct format string or (format, display_func) tuple
        statics: Dictionary of class-level constants
        payload: Whether packet has variable payload
        payload_size_field: Field name containing payload size (if size is in header)
        payload_offset: Offset to add to payload size field value
        vlf: Variable length field name
        vlf_size_field: Field name containing VLF size

    Returns:
        Packet class that can parse and create packets

    Example:
        >>> Header = make_packet("Header", (
        ...     ("version", "B"),
        ...     ("length", "H"),
        ... ))
        >>> pkt = Header(data)  # Parse from bytes
        >>> pkt = Header(1, 100, payload=b"data")  # Create new
        >>> bytes(pkt)  # Serialize to bytes
    """
    if statics is None:
        statics = {}

    fields_dict = OrderedDict(fields)

    # --- Build construct Struct for the fixed-size header -----------------
    cs_fields: list = []
    for field_name, field_spec in fields_dict.items():
        raw_fmt = field_spec[0] if isinstance(field_spec, tuple) else field_spec
        cs_fields.append(field_name / _struct_fmt_to_construct(field_name, raw_fmt))

    cs_struct = cs.Struct(*cs_fields)
    size: int = cs_struct.sizeof()

    # Keep the struct fmt string for backward compat (some code reads .fmt)
    fmt = ">" + "".join((f[0] if isinstance(f, tuple) else f) for f in fields_dict.values())

    # Build field list for namedtuple
    field_names = list(fields_dict.keys())
    if vlf is not None:
        field_names.append(vlf)
    if payload:
        field_names.append("payload")

    base_tuple = namedtuple(name, field_names)

    class PacketClass(base_tuple):
        """Packet class created by make_packet factory (construct-backed)."""

        def __new__(cls, *args: Any, **kwargs: Any) -> PacketClass:
            # Parse mode: single bytes argument
            if len(args) == 1 and isinstance(args[0], (bytes, memoryview)):
                data = bytes(args[0])

                if len(data) < size:
                    raise ValueError(
                        f"{name}: insufficient data, need {size} bytes, got {len(data)}"
                    )

                # Parse fixed-size fields via construct
                parsed = cs_struct.parse(data[:size])
                unpacked = tuple(parsed[fn] for fn in fields_dict.keys())

                kw: Dict[str, Any] = {}

                # Handle variable length field
                if vlf is not None:
                    vlf_size = unpacked[list(fields_dict.keys()).index(vlf_size_field)]
                    kw[vlf] = data[size : size + vlf_size]
                    vlf_actual_size = vlf_size
                else:
                    vlf_actual_size = 0

                # Handle payload
                if payload:
                    if payload_size_field is not None:
                        pl_size = (
                            unpacked[list(fields_dict.keys()).index(payload_size_field)]
                            + payload_offset
                        )
                        kw["payload"] = data[
                            size + vlf_actual_size : size + vlf_actual_size + pl_size
                        ]
                    else:
                        kw["payload"] = data[size + vlf_actual_size :]

                return base_tuple.__new__(cls, *unpacked, **kw)

            # Create mode: explicit field values
            return base_tuple.__new__(cls, *args, **kwargs)

        def __repr__(self) -> str:
            """Detailed representation for debugging."""
            field_strs = []
            for k in fields_dict.keys():
                v = getattr(self, k)
                if isinstance(v, bytes) and len(v) <= 6:
                    field_strs.append(f"{k}={v.hex()}")
                elif isinstance(v, bytes):
                    field_strs.append(f"{k}=<{len(v)} bytes>")
                elif isinstance(v, int):
                    field_strs.append(f"{k}=0x{v:x}")
                else:
                    field_strs.append(f"{k}={v!r}")
            return f"{name}({', '.join(field_strs)})"

        def __str__(self) -> str:
            """Format packet as human-readable string."""
            lines = [f"{name} packet ({len(self)} bytes)"]
            for k, v in fields_dict.items():
                value = getattr(self, k)
                if isinstance(v, tuple):
                    if isinstance(v[1], str):
                        formatted = v[1] % value
                    else:
                        formatted = v[1](value)
                else:
                    formatted = str(value)
                lines.append(f"  {k}: {formatted}")
            return "\n".join(lines)

        def __bytes__(self) -> bytes:
            """Serialize packet to bytes via construct."""
            build_dict = {}
            for key in fields_dict.keys():
                build_dict[key] = getattr(self, key)
            packed = cs_struct.build(build_dict)
            if vlf is not None:
                packed += bytes(getattr(self, vlf))
            if payload:
                packed += bytes(self.payload)
            return packed

        def __len__(self) -> int:
            """Get total packet size in bytes."""
            total = size
            if vlf is not None:
                total += len(bytes(getattr(self, vlf)))
            if payload:
                total += len(self.payload)
            return total

    # Set class attributes
    PacketClass.fmt = fmt
    PacketClass.fmt_size = size
    PacketClass.cs_struct = cs_struct
    PacketClass.__name__ = name
    PacketClass.__qualname__ = name

    for k, v in statics.items():
        setattr(PacketClass, k, v)

    return PacketClass
