"""
PROFINET Alarm Listener.

Provides background alarm reception for established AlarmCR connections.
Receives alarm notifications from devices and invokes registered callbacks.

Per IEC 61158-6-10:
- Alarms are sent via Layer 2 (RTA-PDU) or UDP
- Controller must acknowledge each alarm with AlarmAck-PDU
- Frame IDs: 0xFC01 (high priority), 0xFE01 (low priority)
"""

from __future__ import annotations

import logging
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import List, Optional

import construct as cs

from .alarms import AlarmNotification, parse_alarm_notification
from .protocol import PNAlarmAckPDU, PNBlockHeader, PNRTAHeader
from .util import ethernet_socket

logger = logging.getLogger(__name__)

# =============================================================================
# Construct Struct Definitions for Alarm Listener
# =============================================================================

# Ethernet header fields: dst_mac(6) + src_mac(6) + ethertype(2) + frame_id(2)
EthernetAlarmHeaderStruct = cs.Struct(
    "dst_mac" / cs.Bytes(6),
    "src_mac" / cs.Bytes(6),
    "ethertype" / cs.Int16ub,
    "frame_id" / cs.Int16ub,
)

# Frame IDs for RT alarms (Layer 2)
FRAME_ID_ALARM_HIGH = 0xFC01
FRAME_ID_ALARM_LOW = 0xFE01

# EtherType for PROFINET
ETHERTYPE_PROFINET = 0x8892

# Pre-built constant bytes for frame construction
_FRAME_ID_ALARM_LOW_BYTES = cs.Int16ub.build(FRAME_ID_ALARM_LOW)
_ETHERTYPE_PROFINET_BYTES = cs.Int16ub.build(ETHERTYPE_PROFINET)


@dataclass
class AlarmEndpoint:
    """Alarm endpoint configuration.

    Contains all information needed to set up alarm reception
    for an established AR with AlarmCR.
    """

    interface: str
    """Network interface name (e.g., 'eth0')."""

    controller_ref: int
    """Controller's local alarm reference (from AlarmCRBlockReq)."""

    device_ref: int
    """Device's local alarm reference (from AlarmCRBlockRes)."""

    device_mac: bytes
    """Device MAC address (6 bytes)."""

    transport: int = 0
    """Transport type: 0=Layer2 (RTA), 1=UDP."""


class AlarmListener:
    """Background listener for PROFINET alarm notifications.

    Runs a background thread that receives alarm frames from devices,
    parses them, invokes registered callbacks, and sends acknowledgments.

    Example:
        >>> endpoint = AlarmEndpoint(
        ...     interface="eth0",
        ...     controller_ref=1,
        ...     device_ref=42,
        ...     device_mac=b"\\xd0\\xc8\\x57\\xe0\\x1c\\x2c",
        ... )
        >>> listener = AlarmListener(endpoint)
        >>> listener.add_callback(lambda alarm: print(f"Alarm: {alarm.alarm_type_name}"))
        >>> listener.start()
        >>> # ... wait for alarms ...
        >>> listener.stop()
    """

    def __init__(self, endpoint: AlarmEndpoint, controller_mac: Optional[bytes] = None):
        """Initialize alarm listener.

        Args:
            endpoint: Alarm endpoint configuration
            controller_mac: Controller MAC address for Layer 2 responses
        """
        self.endpoint = endpoint
        self.controller_mac = controller_mac or b"\x00\x00\x00\x00\x00\x00"

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable[[AlarmNotification], None]] = []
        self._sock: Optional[socket.socket] = None

        # Sequence tracking for RTA
        self._send_seq_num: int = 0
        self._recv_seq_num: int = 0

    def add_callback(self, callback: Callable[[AlarmNotification], None]) -> None:
        """Register callback for received alarms.

        Callbacks are invoked from the listener thread for each
        successfully parsed alarm notification.

        Args:
            callback: Function that receives AlarmNotification
        """
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[AlarmNotification], None]) -> None:
        """Remove a registered callback.

        Args:
            callback: Previously registered callback to remove
        """
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def start(self) -> None:
        """Start background alarm listener.

        Creates socket and spawns listener thread.
        Safe to call multiple times (no-op if already running).
        """
        if self._running:
            return

        self._running = True
        self._sock = self._create_socket()
        self._thread = threading.Thread(
            target=self._listen_loop,
            daemon=True,
            name=f"AlarmListener-{self.endpoint.interface}",
        )
        self._thread.start()
        logger.info(
            f"Alarm listener started on {self.endpoint.interface} "
            f"(controller_ref={self.endpoint.controller_ref})"
        )

    def stop(self) -> None:
        """Stop alarm listener.

        Signals thread to stop and waits for graceful shutdown.
        """
        if not self._running:
            return

        self._running = False

        # Close socket to unblock recv
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

        # Wait for thread to finish
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
            if self._thread.is_alive():
                logger.warning("Alarm listener thread did not stop cleanly")

        self._sock = None
        self._thread = None
        logger.info("Alarm listener stopped")

    @property
    def is_running(self) -> bool:
        """True if listener is currently running."""
        return self._running

    def _create_socket(self):
        """Create raw socket for Layer 2 or UDP socket.

        Returns:
            Configured socket for alarm reception.
            For Layer 2: platform-abstracted raw socket (AF_PACKET on Linux,
            NpcapSocket on Windows).
            For UDP: standard socket.

        Raises:
            PermissionError: If raw socket requires elevated privileges
        """
        if self.endpoint.transport == 0:
            # Layer 2 raw socket via platform-abstracted ethernet_socket()
            try:
                sock = ethernet_socket(self.endpoint.interface, ETHERTYPE_PROFINET)
            except PermissionError as e:
                raise PermissionError(f"Raw socket requires root/admin privileges: {e}") from e
        else:
            # UDP socket (port 34964) — works on all platforms
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 34964))  # nosec B104 — must receive from any interface

        # Non-blocking timeout for clean shutdown
        sock.settimeout(1.0)
        return sock

    def _listen_loop(self) -> None:
        """Main listening loop (runs in background thread)."""
        logger.debug("Alarm listener thread started")

        while self._running:
            try:
                if self.endpoint.transport == 0:
                    self._handle_layer2_frame()
                else:
                    self._handle_udp_frame()
            except TimeoutError:
                # Normal timeout, check if we should stop
                continue
            except OSError as e:
                if self._running:
                    logger.error(f"Alarm listener socket error: {e}")
                break
            except Exception as e:
                logger.error(f"Alarm listener error: {e}", exc_info=True)

        logger.debug("Alarm listener thread stopped")

    def _handle_layer2_frame(self) -> None:
        """Process Layer 2 Ethernet frame."""
        data = self._sock.recv(4096)

        if len(data) < 16:
            return

        # Parse Ethernet header (14 bytes) + Frame ID (2 bytes)
        eth_hdr = EthernetAlarmHeaderStruct.parse(data[:16])

        if eth_hdr.ethertype != ETHERTYPE_PROFINET:
            return

        # Check source MAC matches device
        if eth_hdr.src_mac != self.endpoint.device_mac:
            return

        if eth_hdr.frame_id == FRAME_ID_ALARM_HIGH:
            self._process_alarm(data[16:], high_priority=True, src_mac=eth_hdr.src_mac)
        elif eth_hdr.frame_id == FRAME_ID_ALARM_LOW:
            self._process_alarm(data[16:], high_priority=False, src_mac=eth_hdr.src_mac)

    def _handle_udp_frame(self) -> None:
        """Process UDP datagram."""
        data, addr = self._sock.recvfrom(4096)

        if len(data) < 28:
            return

        # For UDP, the frame starts with the alarm block directly
        # (no Ethernet header, no Frame ID)
        self._process_alarm(data, high_priority=None, src_addr=addr)

    def _process_alarm(
        self,
        payload: bytes,
        high_priority: Optional[bool],
        src_mac: Optional[bytes] = None,
        src_addr: Optional[tuple] = None,
    ) -> None:
        """Parse alarm and invoke callbacks.

        Args:
            payload: Alarm payload (after Frame ID for Layer 2)
            high_priority: True for high, False for low, None for UDP
            src_mac: Source MAC for Layer 2 response
            src_addr: Source address for UDP response
        """
        try:
            # Parse RTA-PDU header if Layer 2
            if self.endpoint.transport == 0 and len(payload) >= 12:
                rta_header = self._parse_rta_header(payload[:12])
                alarm_data = payload[12:]

                # Validate alarm references
                if rta_header.alarm_dst_endpoint != self.endpoint.controller_ref:
                    logger.debug(
                        f"Ignoring alarm with wrong dst ref "
                        f"(got {rta_header.alarm_dst_endpoint}, "
                        f"expected {self.endpoint.controller_ref})"
                    )
                    return

                self._recv_seq_num = rta_header.send_seq_num
            else:
                alarm_data = payload
                rta_header = None

            # Parse alarm notification
            alarm = parse_alarm_notification(alarm_data)

            # Set priority from frame ID if not from block type
            if high_priority is not None:
                # Verify consistency or trust frame ID
                pass

            logger.debug(
                f"Received alarm: {alarm.alarm_type_name} "
                f"at {alarm.location} (seq={alarm.alarm_sequence_number})"
            )

            # Send acknowledgment
            self._send_ack(alarm, src_mac, src_addr)

            # Invoke callbacks
            for callback in self._callbacks:
                try:
                    callback(alarm)
                except Exception as e:
                    logger.error(f"Alarm callback error: {e}", exc_info=True)

        except ValueError as e:
            logger.warning(f"Failed to parse alarm: {e}")
        except Exception as e:
            logger.error(f"Alarm processing error: {e}", exc_info=True)

    def _parse_rta_header(self, data: bytes) -> PNRTAHeader:
        """Parse RTA-PDU header."""
        return PNRTAHeader(data)

    def _send_ack(
        self,
        alarm: AlarmNotification,
        src_mac: Optional[bytes],
        src_addr: Optional[tuple],
    ) -> None:
        """Send AlarmAck-PDU back to device.

        Args:
            alarm: Parsed alarm to acknowledge
            src_mac: Device MAC for Layer 2 response
            src_addr: Device address for UDP response
        """
        try:
            # Build AlarmAck PDU
            block_type = 0x8001 if alarm.is_high_priority else 0x8002  # Ack High/Low
            block_length = PNAlarmAckPDU.fmt_size - 4  # Exclude type+length

            block_header = PNBlockHeader(
                block_type,
                block_length,
                0x01,  # version high
                0x00,  # version low
            )

            # Reconstruct alarm specifier
            alarm_specifier = (
                (alarm.alarm_sequence_number & 0x07FF)
                | (0x0800 if alarm.channel_diagnosis else 0)
                | (0x1000 if alarm.manufacturer_specific else 0)
                | (0x2000 if alarm.submodule_diagnosis_state else 0)
                | (0x4000 if alarm.ar_diagnosis_state else 0)
            )

            ack = PNAlarmAckPDU(
                block_header=bytes(block_header),
                alarm_type=alarm.alarm_type,
                api=alarm.api,
                slot_number=alarm.slot_number,
                subslot_number=alarm.subslot_number,
                alarm_specifier=alarm_specifier,
                pnio_status=0x00000000,  # OK
            )
            ack_data = bytes(ack)

            if self.endpoint.transport == 0:
                # Layer 2 with RTA header
                self._send_layer2_ack(ack_data, src_mac, alarm.is_high_priority)
            else:
                # UDP
                self._send_udp_ack(ack_data, src_addr)

            logger.debug(
                f"Sent AlarmAck for {alarm.alarm_type_name} (seq={alarm.alarm_sequence_number})"
            )

        except Exception as e:
            logger.error(f"Failed to send AlarmAck: {e}")

    def _send_layer2_ack(
        self, ack_data: bytes, dst_mac: bytes, high_priority: bool = False
    ) -> None:
        """Send acknowledgment via Layer 2.

        Args:
            ack_data: Serialized AlarmAck PDU
            dst_mac: Destination MAC address
            high_priority: True for high-priority alarm ack frame ID
        """
        # Build RTA header
        self._send_seq_num = (self._send_seq_num + 1) & 0xFFFF

        rta_header = PNRTAHeader(
            alarm_dst_endpoint=self.endpoint.device_ref,
            alarm_src_endpoint=self.endpoint.controller_ref,
            pdu_type=(PNRTAHeader.RTA_TYPE_DATA << 4) | PNRTAHeader.VERSION_1,
            add_flags=0,
            send_seq_num=self._send_seq_num,
            ack_seq_num=self._recv_seq_num,
            var_part_len=len(ack_data),
            payload=b"",
        )

        # Build complete frame with priority-matching frame ID
        frame_id_bytes = (
            cs.Int16ub.build(FRAME_ID_ALARM_HIGH) if high_priority else _FRAME_ID_ALARM_LOW_BYTES
        )
        eth_frame = (
            dst_mac
            + self.controller_mac
            + _ETHERTYPE_PROFINET_BYTES
            + frame_id_bytes
            + bytes(rta_header)
            + ack_data
        )

        try:
            self._sock.send(eth_frame)
        except Exception as e:
            logger.error(f"Layer 2 send error: {e}")

    def _send_udp_ack(self, ack_data: bytes, dst_addr: tuple) -> None:
        """Send acknowledgment via UDP.

        Args:
            ack_data: Serialized AlarmAck PDU
            dst_addr: Destination (ip, port) tuple
        """
        try:
            self._sock.sendto(ack_data, dst_addr)
        except Exception as e:
            logger.error(f"UDP send error: {e}")

    def __enter__(self) -> AlarmListener:
        """Context manager entry - start listener."""
        self.start()
        return self

    def __exit__(self, *args) -> None:
        """Context manager exit - stop listener."""
        self.stop()
