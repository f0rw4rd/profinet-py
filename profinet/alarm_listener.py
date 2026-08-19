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
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import List, Optional

import construct as cs

from .alarms import AlarmNotification, parse_alarm_notification
from .protocol import PNAlarmAckPDU, PNBlockHeader, PNRTAHeader
from .util import ethernet_socket, skip_vlan_tags

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

# RTA AddFlags bits: window size in bits 0-3, TACK (transport ack request)
# in bit 4 (IEC 61158-6-10; cf. p-net pf_put_alarm_fixed)
ADD_FLAGS_WINDOW_1 = 0x01
ADD_FLAGS_TACK = 0x10

# RTA sequence numbers start at 0xFFFF and wrap modulo 0x8000 after ack
SEQ_NUM_INIT = 0xFFFF
SEQ_NUM_INIT_O = 0xFFFE
SEQ_NUM_MASK = 0x7FFF

# 802.1Q priority tags for alarm frames per IEC 61158-6-10: PCP 6 for the
# high-priority alarm CR, PCP 5 for low priority, VID 0 (matching the
# negotiated AlarmCRTagHeaderHigh/Low values 0xC000/0xA000)
VLAN_TAG_ALARM_HIGH = b"\x81\x00\xc0\x00"
VLAN_TAG_ALARM_LOW = b"\x81\x00\xa0\x00"


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

    rta_timeout_factor: int = 1
    """Negotiated RTATimeoutFactor (retransmit interval = factor x 100ms)."""

    rta_retries: int = 3
    """Negotiated RTARetries (retransmissions before giving up)."""


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

        # RTA sequence counters (APMS send side / APMR receive side).
        # *_o holds the last acknowledged/accepted value.
        self._send_seq_num: int = SEQ_NUM_INIT
        self._send_seq_num_o: int = SEQ_NUM_INIT_O
        self._exp_seq_num: int = SEQ_NUM_INIT
        self._exp_seq_num_o: int = SEQ_NUM_INIT_O

        # Retransmission state for our unacknowledged AlarmAck DATA PDU:
        # [frame bytes, next retransmit time (monotonic), retries left].
        # Accessed only from the listener thread.
        self._pending_ack: Optional[list] = None

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
            # Layer 2 raw socket via platform-abstracted ethernet_socket().
            # Bind ETH_P_ALL (ethertype=None): a socket bound to 0x8892 never
            # sees VLAN-tagged alarm frames unless the NIC strips the tag.
            try:
                sock = ethernet_socket(self.endpoint.interface, None)
            except PermissionError as e:
                raise PermissionError(f"Raw socket requires root/admin privileges: {e}") from e
        else:
            # UDP socket (port 34964) — works on all platforms
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 34964))  # nosec B104 — must receive from any interface

        # Short timeout: bounds shutdown latency and paces the AlarmAck
        # retransmission check (100ms base interval)
        sock.settimeout(0.1)
        return sock

    def _listen_loop(self) -> None:
        """Main listening loop (runs in background thread)."""
        logger.debug("Alarm listener thread started")

        while self._running:
            try:
                self._check_retransmit()
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

        # Parse Ethernet header, skipping any 802.1Q priority tags
        src_mac = data[6:12]
        eth_offset = skip_vlan_tags(data)
        if len(data) < eth_offset + 4:
            return
        ethertype = int.from_bytes(data[eth_offset : eth_offset + 2], "big")

        if ethertype != ETHERTYPE_PROFINET:
            return

        # Check source MAC matches device
        if src_mac != self.endpoint.device_mac:
            return

        frame_id = int.from_bytes(data[eth_offset + 2 : eth_offset + 4], "big")
        if frame_id == FRAME_ID_ALARM_HIGH:
            self._process_alarm(data[eth_offset + 4 :], high_priority=True, src_mac=src_mac)
        elif frame_id == FRAME_ID_ALARM_LOW:
            self._process_alarm(data[eth_offset + 4 :], high_priority=False, src_mac=src_mac)

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

                # pdu_type byte: version in high nibble, type in low nibble
                version = (rta_header.pdu_type >> 4) & 0x0F
                pdu_type = rta_header.pdu_type & 0x0F
                if version != PNRTAHeader.VERSION_1:
                    logger.debug(f"Ignoring RTA PDU with version {version}")
                    return

                if pdu_type == PNRTAHeader.RTA_TYPE_ACK:
                    self._handle_transport_ack(rta_header)
                    return
                if pdu_type == PNRTAHeader.RTA_TYPE_NACK:
                    logger.warning(
                        f"RTA NACK from device (ack_seq={rta_header.ack_seq_num}), "
                        f"sequence error on our side"
                    )
                    return
                if pdu_type == PNRTAHeader.RTA_TYPE_ERR:
                    status = int.from_bytes(alarm_data[:4], "big") if len(alarm_data) >= 4 else 0
                    logger.error(f"RTA ERROR PDU from device, PNIOStatus=0x{status:08X}")
                    return
                if pdu_type != PNRTAHeader.RTA_TYPE_DATA:
                    logger.debug(f"Ignoring RTA PDU type {pdu_type}")
                    return

                # DATA PDU: transport-acknowledge handshake (APMR side).
                if not (rta_header.add_flags & ADD_FLAGS_TACK):
                    return
                if rta_header.send_seq_num == self._exp_seq_num_o:
                    # Retransmission of an already-accepted PDU: re-ack only
                    self._send_transport_ack(src_mac, bool(high_priority))
                    return
                if rta_header.send_seq_num != self._exp_seq_num:
                    logger.warning(
                        f"RTA sequence error (got {rta_header.send_seq_num}, "
                        f"expected {self._exp_seq_num}), sending NACK"
                    )
                    self._send_nack(src_mac, bool(high_priority))
                    return

                # In sequence: advance receive counters
                self._exp_seq_num_o = self._exp_seq_num
                self._exp_seq_num = (self._exp_seq_num + 1) & SEQ_NUM_MASK

                # A DATA PDU may piggyback the ack for our last DATA
                if rta_header.ack_seq_num == self._send_seq_num:
                    self._send_seq_num_o = self._send_seq_num
                    self._send_seq_num = (self._send_seq_num + 1) & SEQ_NUM_MASK
                    self._pending_ack = None

                # The device retransmits and then aborts the AR without this
                self._send_transport_ack(src_mac, bool(high_priority))
            else:
                alarm_data = payload
                rta_header = None

            # Parse alarm notification
            alarm = parse_alarm_notification(alarm_data)

            logger.debug(
                f"Received alarm: {alarm.alarm_type_name} "
                f"at {alarm.location} (seq={alarm.alarm_sequence_number})"
            )

            # Send application-level AlarmAck
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

    def _handle_transport_ack(self, rta_header) -> None:
        """Handle a pure RTA-ACK PDU confirming our last DATA PDU."""
        if rta_header.ack_seq_num == self._send_seq_num:
            self._send_seq_num_o = self._send_seq_num
            self._send_seq_num = (self._send_seq_num + 1) & SEQ_NUM_MASK
            self._pending_ack = None
            logger.debug(f"RTA transport ack received (seq={rta_header.ack_seq_num})")
        else:
            logger.debug(
                f"Stale RTA ack (ack_seq={rta_header.ack_seq_num}, expected {self._send_seq_num})"
            )

    def _build_rta_frame(
        self,
        pdu_type: int,
        add_flags: int,
        send_seq_num: int,
        ack_seq_num: int,
        var_part: bytes,
        dst_mac: bytes,
        high_priority: bool,
    ) -> bytes:
        """Build a complete Ethernet frame carrying an RTA PDU."""
        rta_header = PNRTAHeader(
            alarm_dst_endpoint=self.endpoint.device_ref,
            alarm_src_endpoint=self.endpoint.controller_ref,
            pdu_type=(PNRTAHeader.VERSION_1 << 4) | pdu_type,
            add_flags=add_flags,
            send_seq_num=send_seq_num,
            ack_seq_num=ack_seq_num,
            var_part_len=len(var_part),
            payload=b"",
        )
        if high_priority:
            vlan_tag = VLAN_TAG_ALARM_HIGH
            frame_id_bytes = cs.Int16ub.build(FRAME_ID_ALARM_HIGH)
        else:
            vlan_tag = VLAN_TAG_ALARM_LOW
            frame_id_bytes = _FRAME_ID_ALARM_LOW_BYTES
        return (
            dst_mac
            + self.controller_mac
            + vlan_tag
            + _ETHERTYPE_PROFINET_BYTES
            + frame_id_bytes
            + bytes(rta_header)
            + var_part
        )

    def _send_frame(self, eth_frame: bytes) -> None:
        try:
            self._sock.send(eth_frame)
        except Exception as e:
            logger.error(f"Layer 2 send error: {e}")

    def _send_rta_frame(
        self,
        pdu_type: int,
        add_flags: int,
        send_seq_num: int,
        ack_seq_num: int,
        var_part: bytes,
        dst_mac: bytes,
        high_priority: bool,
    ) -> bytes:
        """Build and send an RTA PDU (Layer 2); returns the frame bytes."""
        eth_frame = self._build_rta_frame(
            pdu_type, add_flags, send_seq_num, ack_seq_num, var_part, dst_mac, high_priority
        )
        self._send_frame(eth_frame)
        return eth_frame

    def _check_retransmit(self) -> None:
        """Retransmit the pending AlarmAck if its transport ACK is overdue.

        Uses the negotiated RTATimeoutFactor (x100ms) and RTARetries; a
        conformant sender aborts the AR after the final timeout - as a
        listener we log the failure and stop retrying.
        """
        if not self._pending_ack:
            return
        frame, next_time, retries_left = self._pending_ack
        if time.monotonic() < next_time:
            return
        if retries_left > 0:
            logger.debug(
                f"AlarmAck transport ACK overdue, retransmitting ({retries_left} retries left)"
            )
            self._send_frame(frame)
            interval = self.endpoint.rta_timeout_factor * 0.1
            self._pending_ack = [frame, time.monotonic() + interval, retries_left - 1]
        else:
            logger.error(
                f"AlarmAck not acknowledged after {self.endpoint.rta_retries} "
                f"retransmissions; device may abort the AR"
            )
            self._pending_ack = None

    def _send_transport_ack(self, dst_mac: bytes, high_priority: bool) -> None:
        """Send a pure RTA-ACK (TACK) with empty var part."""
        self._send_rta_frame(
            PNRTAHeader.RTA_TYPE_ACK,
            ADD_FLAGS_WINDOW_1,
            self._send_seq_num_o,
            self._exp_seq_num_o,
            b"",
            dst_mac,
            high_priority,
        )

    def _send_nack(self, dst_mac: bytes, high_priority: bool) -> None:
        """Send an RTA-NACK for an out-of-sequence DATA PDU."""
        self._send_rta_frame(
            PNRTAHeader.RTA_TYPE_NACK,
            ADD_FLAGS_WINDOW_1,
            self._send_seq_num_o,
            self._exp_seq_num_o,
            b"",
            dst_mac,
            high_priority,
        )

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

            # Reconstruct alarm specifier (ARDiagnosisState is bit 15; bit 14
            # is reserved)
            alarm_specifier = (
                (alarm.alarm_sequence_number & 0x07FF)
                | (0x0800 if alarm.channel_diagnosis else 0)
                | (0x1000 if alarm.manufacturer_specific else 0)
                | (0x2000 if alarm.submodule_diagnosis_state else 0)
                | (0x8000 if alarm.ar_diagnosis_state else 0)
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
        """Send the AlarmAck as a DATA PDU with the TACK flag set.

        Uses the current send sequence number; the counter advances only
        when the device acknowledges (pure ACK or piggybacked in DATA).

        Args:
            ack_data: Serialized AlarmAck PDU
            dst_mac: Destination MAC address
            high_priority: True for high-priority alarm ack frame ID
        """
        frame = self._send_rta_frame(
            PNRTAHeader.RTA_TYPE_DATA,
            ADD_FLAGS_WINDOW_1 | ADD_FLAGS_TACK,
            self._send_seq_num,
            self._exp_seq_num_o,
            ack_data,
            dst_mac,
            high_priority,
        )
        interval = self.endpoint.rta_timeout_factor * 0.1
        self._pending_ack = [frame, time.monotonic() + interval, self.endpoint.rta_retries]

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
