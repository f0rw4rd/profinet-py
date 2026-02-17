"""
PROFINET Real-Time Frame Handling.

Provides data structures for RT_CLASS_1 cyclic data exchange:
- RTFrame: Cyclic frame serialization/deserialization
- IOCRConfig: IOCR configuration from AR setup
- IODataObject: Individual IO data object within C_SDU
- CyclicDataBuilder: Build C_SDU payload from IO objects

Per IEC 61158-6-10:
- RT frames use EtherType 0x8892
- Frame IDs 0x8000-0xFBFF for RT_CLASS_1
- C_SDU contains process data + IOxS status bytes
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import List, Optional

import construct as cs

# EtherType for PROFINET RT frames
ETHERTYPE_PROFINET = 0x8892

# Pre-built ethertype bytes for frame construction
_ETHERTYPE_PROFINET_BYTES = cs.Int16ub.build(ETHERTYPE_PROFINET)

# =============================================================================
# Construct Struct Definitions for RT Frame Parsing
# =============================================================================

# RT frame header: just the frame ID
RTFrameIdStruct = cs.Struct(
    "frame_id" / cs.Int16ub,
)

# RT frame trailer: cycle counter + data status + transfer status
RTFrameTrailerStruct = cs.Struct(
    "cycle_counter" / cs.Int16ub,
    "data_status" / cs.Int8ub,
    "transfer_status" / cs.Int8ub,
)

# Ethernet header ethertype at offset 12
EtherTypeStruct = cs.Struct(
    "ethertype" / cs.Int16ub,
)

# Frame ID ranges
FRAME_ID_RT_CLASS_1_MIN = 0x8000
FRAME_ID_RT_CLASS_1_MAX = 0xFBFF
FRAME_ID_ALARM_HIGH = 0xFC01
FRAME_ID_ALARM_LOW = 0xFE01

# IOCR types
IOCR_TYPE_INPUT = 1  # Device -> Controller
IOCR_TYPE_OUTPUT = 2  # Controller -> Device

# RT Class values
RT_CLASS_1 = 0x01  # Software scheduled (250µs - 512ms)
RT_CLASS_2 = 0x02  # Hardware scheduled (reserved)
RT_CLASS_3 = 0x03  # IRT (isochronous, hardware only)

# DataStatus bit definitions
DATA_STATUS_STATE = 0x01  # 0=Backup, 1=Primary
DATA_STATUS_REDUNDANCY = 0x02  # Redundancy state
DATA_STATUS_VALID = 0x04  # 0=Invalid, 1=Valid
DATA_STATUS_RESERVED = 0x08
DATA_STATUS_PROVIDER_RUN = 0x10  # 0=Stop, 1=Run
DATA_STATUS_STATION_OK = 0x20  # 0=Problem, 1=OK
DATA_STATUS_IGNORE = 0x80  # 1=Ignore frame

# IOxS (Provider/Consumer Status) values
IOXS_GOOD = 0x80  # Good data, subslot level
IOXS_BAD = 0x00  # Bad data
IOXS_EXTENSION = 0x01  # More IOxS follows


@dataclass
class IODataObject:
    """Single IO data object within C_SDU.

    Represents one piece of process data mapped to a slot/subslot.
    """

    slot: int
    """Slot number."""

    subslot: int
    """Subslot number."""

    frame_offset: int
    """Offset within C_SDU payload for data."""

    data_length: int
    """Length of process data in bytes."""

    iops_offset: int
    """Offset for IOPS (Provider Status) byte."""

    iocs_offset: int = 0
    """Offset for IOCS (Consumer Status) byte, if applicable."""


@dataclass
class IOCRConfig:
    """IOCR configuration from AR setup.

    Contains timing parameters and IO object mappings
    needed for cyclic data exchange.
    """

    iocr_type: int
    """IOCR type: 1=Input (device->controller), 2=Output (controller->device)."""

    iocr_reference: int
    """Local IOCR reference number."""

    frame_id: int
    """Assigned Frame ID (0x8000-0xFBFF for RT_CLASS_1)."""

    send_clock_factor: int = 32
    """Base clock multiplier (32 = 1ms base)."""

    reduction_ratio: int = 32
    """Update rate reduction (1 = every cycle)."""

    phase: int = 0
    """Phase offset within cycle."""

    watchdog_factor: int = 3
    """Watchdog multiplier (timeout = watchdog_factor * cycle_time)."""

    data_length: int = 40
    """Total C_SDU length (minimum 40 bytes)."""

    objects: List[IODataObject] = field(default_factory=list)
    """List of IO data objects within this IOCR."""

    @property
    def cycle_time_us(self) -> int:
        """Calculate cycle time in microseconds.

        Base clock is 31.25µs per IEC 61158.
        cycle_time = reduction_ratio * send_clock_factor * 31.25µs
        """
        # Using integer math: 31.25 = 125/4
        return (self.reduction_ratio * self.send_clock_factor * 125) // 4

    @property
    def cycle_time_ms(self) -> float:
        """Calculate cycle time in milliseconds."""
        return self.cycle_time_us / 1000.0

    @property
    def watchdog_time_us(self) -> int:
        """Calculate watchdog timeout in microseconds."""
        return self.watchdog_factor * self.cycle_time_us

    @property
    def is_input(self) -> bool:
        """True if this is an Input IOCR (device->controller)."""
        return self.iocr_type == IOCR_TYPE_INPUT

    @property
    def is_output(self) -> bool:
        """True if this is an Output IOCR (controller->device)."""
        return self.iocr_type == IOCR_TYPE_OUTPUT


@dataclass
class RTFrame:
    """PROFINET Real-Time cyclic frame.

    Represents a single RT frame including:
    - Frame ID (identifies the IOCR)
    - C_SDU payload (process data + IOxS)
    - Cycle counter and status

    Example:
        >>> # Parse incoming frame
        >>> frame = RTFrame.from_bytes(data[14:])  # Skip Ethernet header
        >>> if frame.is_valid and frame.is_running:
        ...     process_data = frame.payload[:4]

        >>> # Build outgoing frame
        >>> frame = RTFrame(
        ...     frame_id=0xC000,
        ...     cycle_counter=1,
        ...     data_status=RTFrame.DATA_VALID | RTFrame.DATA_RUN,
        ...     transfer_status=0,
        ...     payload=payload,
        ... )
        >>> eth_frame = dst_mac + src_mac + ETHERTYPE + frame.to_bytes()
    """

    frame_id: int
    """Frame ID identifying the IOCR (0x8000-0xFBFF for RT_CLASS_1)."""

    cycle_counter: int
    """16-bit cycle counter, increments each cycle."""

    data_status: int
    """DataStatus byte with validity and state flags."""

    transfer_status: int
    """TransferStatus byte (usually 0)."""

    payload: bytes
    """C_SDU payload containing process data and IOxS."""

    # DataStatus convenience constants
    DATA_VALID = DATA_STATUS_VALID
    DATA_PRIMARY = DATA_STATUS_STATE
    DATA_RUN = DATA_STATUS_PROVIDER_RUN
    DATA_OK = DATA_STATUS_STATION_OK

    @classmethod
    def from_bytes(cls, data: bytes) -> RTFrame:
        """Parse RT frame from raw bytes (after Ethernet header).

        Args:
            data: Raw bytes starting with Frame ID

        Returns:
            Parsed RTFrame

        Raises:
            ValueError: If data is too short
        """
        if len(data) < 6:
            raise ValueError(f"RT frame too short: {len(data)} bytes")

        header = RTFrameIdStruct.parse(data[:2])
        trailer = RTFrameTrailerStruct.parse(data[-4:])

        return cls(
            frame_id=header.frame_id,
            cycle_counter=trailer.cycle_counter,
            data_status=trailer.data_status,
            transfer_status=trailer.transfer_status,
            payload=data[2:-4],
        )

    def to_bytes(self) -> bytes:
        """Serialize RT frame to bytes.

        Returns:
            Serialized frame (Frame ID + payload + cycle + status)
        """
        return (
            RTFrameIdStruct.build({"frame_id": self.frame_id})
            + self.payload
            + RTFrameTrailerStruct.build(
                {
                    "cycle_counter": self.cycle_counter,
                    "data_status": self.data_status,
                    "transfer_status": self.transfer_status,
                }
            )
        )

    @property
    def is_valid(self) -> bool:
        """True if data is valid (DataStatus bit 2)."""
        return bool(self.data_status & DATA_STATUS_VALID)

    @property
    def is_running(self) -> bool:
        """True if provider is running (DataStatus bit 4)."""
        return bool(self.data_status & DATA_STATUS_PROVIDER_RUN)

    @property
    def is_ok(self) -> bool:
        """True if station is OK (DataStatus bit 5)."""
        return bool(self.data_status & DATA_STATUS_STATION_OK)

    @property
    def is_primary(self) -> bool:
        """True if this is primary data (DataStatus bit 0)."""
        return bool(self.data_status & DATA_STATUS_STATE)

    def __repr__(self) -> str:
        flags = []
        if self.is_valid:
            flags.append("VALID")
        if self.is_running:
            flags.append("RUN")
        if self.is_ok:
            flags.append("OK")
        if self.is_primary:
            flags.append("PRIMARY")
        flags_str = "|".join(flags) if flags else "NONE"
        return (
            f"RTFrame(id=0x{self.frame_id:04X}, "
            f"cycle={self.cycle_counter}, "
            f"status={flags_str}, "
            f"payload={len(self.payload)}B)"
        )


class CyclicDataBuilder:
    """Builds C_SDU payload from IO data objects with double-buffering.

    Uses two buffers for lock-free reads by the TX thread:
    - _write_buffer: application thread writes here via set_data()
    - _send_buffer: TX thread reads here via build()

    The swap() method atomically promotes the write buffer to send buffer.
    This minimizes lock contention between application and TX threads.

    Example:
        >>> config = IOCRConfig(
        ...     iocr_type=2, frame_id=0xC000, data_length=48,
        ...     objects=[
        ...         IODataObject(slot=1, subslot=1, frame_offset=0,
        ...                      data_length=8, iops_offset=8),
        ...     ]
        ... )
        >>> builder = CyclicDataBuilder(config)
        >>> builder.set_data(1, 1, b"\\x11\\x22\\x33\\x44\\x55\\x66\\x77\\x88")
        >>> builder.set_iops(1, 1, IOXS_GOOD)
        >>> builder.swap()  # promote to send buffer
        >>> payload = builder.build()  # reads from send buffer
    """

    def __init__(self, config: IOCRConfig):
        """Initialize builder with IOCR configuration.

        Args:
            config: IOCRConfig with data length and object mappings
        """
        self.config = config
        self._write_buffer = bytearray(config.data_length)
        self._send_buffer = bytearray(config.data_length)
        self._write_lock = threading.Lock()
        self._dirty = False

    def set_data(self, slot: int, subslot: int, data: bytes) -> None:
        """Set process data for a slot/subslot.

        Thread-safe. Writes to the write buffer.

        Args:
            slot: Slot number
            subslot: Subslot number
            data: Process data bytes

        Raises:
            ValueError: If slot/subslot not found in config
        """
        for obj in self.config.objects:
            if obj.slot == slot and obj.subslot == subslot:
                end = obj.frame_offset + min(len(data), obj.data_length)
                with self._write_lock:
                    self._write_buffer[obj.frame_offset : end] = data[: obj.data_length]
                    self._dirty = True
                return
        raise ValueError(f"Unknown slot/subslot: {slot}/{subslot}")

    def get_data(self, slot: int, subslot: int) -> bytes:
        """Get process data for a slot/subslot from write buffer.

        Args:
            slot: Slot number
            subslot: Subslot number

        Returns:
            Process data bytes

        Raises:
            ValueError: If slot/subslot not found in config
        """
        for obj in self.config.objects:
            if obj.slot == slot and obj.subslot == subslot:
                with self._write_lock:
                    return bytes(
                        self._write_buffer[obj.frame_offset : obj.frame_offset + obj.data_length]
                    )
        raise ValueError(f"Unknown slot/subslot: {slot}/{subslot}")

    def set_iops(self, slot: int, subslot: int, status: int = IOXS_GOOD) -> None:
        """Set Provider Status (IOPS) for a slot/subslot.

        Skips IOCS-only objects (data_length == 0) which have no IOPS byte.

        Args:
            slot: Slot number
            subslot: Subslot number
            status: IOPS value (default: IOXS_GOOD = 0x80)
        """
        for obj in self.config.objects:
            if obj.slot == slot and obj.subslot == subslot:
                if obj.data_length > 0:
                    with self._write_lock:
                        self._write_buffer[obj.iops_offset] = status
                        self._dirty = True
                return

    def set_iocs(self, slot: int, subslot: int, status: int = IOXS_GOOD) -> None:
        """Set Consumer Status (IOCS) for a slot/subslot.

        Args:
            slot: Slot number
            subslot: Subslot number
            status: IOCS value (default: IOXS_GOOD = 0x80)
        """
        for obj in self.config.objects:
            if obj.slot == slot and obj.subslot == subslot:
                if obj.iocs_offset > 0:
                    with self._write_lock:
                        self._write_buffer[obj.iocs_offset] = status
                        self._dirty = True
                return

    def set_all_iops(self, status: int = IOXS_GOOD) -> None:
        """Set IOPS for all objects that carry process data.

        Skips IOCS-only objects (data_length == 0) which have no IOPS byte.

        Args:
            status: IOPS value for all objects
        """
        with self._write_lock:
            for obj in self.config.objects:
                if obj.data_length > 0:
                    self._write_buffer[obj.iops_offset] = status
            self._dirty = True

    def set_all_iocs(self, status: int = IOXS_GOOD) -> None:
        """Set IOCS for all objects that have iocs_offset.

        Args:
            status: IOCS value for all objects
        """
        with self._write_lock:
            for obj in self.config.objects:
                if obj.iocs_offset > 0:
                    self._write_buffer[obj.iocs_offset] = status
            self._dirty = True

    def clear(self) -> None:
        """Clear all data to zeros."""
        with self._write_lock:
            for i in range(len(self._write_buffer)):
                self._write_buffer[i] = 0
            self._dirty = True

    def swap(self) -> None:
        """Swap write buffer into send buffer.

        Called by TX thread at the start of each cycle. Only copies
        if the write buffer has been modified since last swap.
        """
        if self._dirty:
            with self._write_lock:
                self._send_buffer[:] = self._write_buffer
                self._dirty = False

    def build(self) -> bytes:
        """Build and return C_SDU payload from send buffer.

        Lock-free - reads from the send buffer which is only
        updated by swap() at the start of each TX cycle.

        Returns:
            Complete payload bytes
        """
        return bytes(self._send_buffer)

    def load(self, payload: bytes) -> None:
        """Load payload data into write buffer.

        Args:
            payload: Received payload bytes
        """
        copy_len = min(len(payload), len(self._write_buffer))
        with self._write_lock:
            self._write_buffer[:copy_len] = payload[:copy_len]
            self._dirty = True


def build_iocr_configs(
    slots,
    input_frame_id: int,
    output_frame_id: int,
    send_clock_factor: int = 32,
    reduction_ratio: int = 32,
    watchdog_factor: int = 3,
):
    """Build IOCRConfig objects for CyclicController from slot definitions.

    Computes frame offsets matching what RPCCon._build_iocr_block builds,
    including IOCS entries for submodules without data in each direction.

    Each slot object must have: slot, subslot, input_length, output_length.

    Args:
        slots: List of slot objects (e.g., IOSlot instances)
        input_frame_id: Frame ID for input IOCR (from ConnectResult)
        output_frame_id: Frame ID for output IOCR (from ConnectResult)
        send_clock_factor: Base clock multiplier (32 = 1ms base)
        reduction_ratio: Update rate reduction
        watchdog_factor: Watchdog multiplier

    Returns:
        Tuple of (input_iocr, output_iocr) as IOCRConfig objects.
        Output IOCR includes IODataObject entries for IOCS-only submodules
        (those with input data but no output data), enabling set_all_iocs()
        to properly acknowledge received input.
    """
    # --- Input IOCR: device -> controller ---
    input_objects = []
    frame_offset = 0
    for s in slots:
        if s.input_length > 0:
            input_objects.append(
                IODataObject(
                    slot=s.slot,
                    subslot=s.subslot,
                    frame_offset=frame_offset,
                    data_length=s.input_length,
                    iops_offset=frame_offset + s.input_length,
                )
            )
            frame_offset += s.input_length + 1  # data + IOPS byte

    # IOCS entries for slots with no input data
    for s in slots:
        if s.input_length == 0:
            frame_offset += 1

    input_iocr = IOCRConfig(
        iocr_type=IOCR_TYPE_INPUT,
        iocr_reference=1,
        frame_id=input_frame_id,
        send_clock_factor=send_clock_factor,
        reduction_ratio=reduction_ratio,
        watchdog_factor=watchdog_factor,
        data_length=max(40, frame_offset),
        objects=input_objects,
    )

    # --- Output IOCR: controller -> device ---
    output_objects = []
    frame_offset = 0
    for s in slots:
        if s.output_length > 0:
            output_objects.append(
                IODataObject(
                    slot=s.slot,
                    subslot=s.subslot,
                    frame_offset=frame_offset,
                    data_length=s.output_length,
                    iops_offset=frame_offset + s.output_length,
                )
            )
            frame_offset += s.output_length + 1  # data + IOPS byte

    # IOCS entries for slots with no output data (PROTO-2/3 fix).
    # These are submodules that have input data but no output data
    # (e.g., DAP submodules). The controller must set their IOCS to
    # GOOD in the output frame to tell the device "I received your input".
    for s in slots:
        if s.output_length == 0:
            output_objects.append(
                IODataObject(
                    slot=s.slot,
                    subslot=s.subslot,
                    frame_offset=frame_offset,
                    data_length=0,
                    iops_offset=0,
                    iocs_offset=frame_offset,
                )
            )
            frame_offset += 1

    output_iocr = IOCRConfig(
        iocr_type=IOCR_TYPE_OUTPUT,
        iocr_reference=2,
        frame_id=output_frame_id,
        send_clock_factor=send_clock_factor,
        reduction_ratio=reduction_ratio,
        watchdog_factor=watchdog_factor,
        data_length=max(40, frame_offset),
        objects=output_objects,
    )

    return input_iocr, output_iocr


def build_ethernet_frame(
    dst_mac: bytes,
    src_mac: bytes,
    rt_frame: RTFrame,
) -> bytes:
    """Build complete Ethernet frame with RT payload.

    Args:
        dst_mac: Destination MAC address (6 bytes)
        src_mac: Source MAC address (6 bytes)
        rt_frame: RT frame to embed

    Returns:
        Complete Ethernet frame bytes
    """
    return dst_mac + src_mac + _ETHERTYPE_PROFINET_BYTES + rt_frame.to_bytes()


def parse_ethernet_frame(data: bytes) -> Optional[RTFrame]:
    """Parse Ethernet frame and extract RT frame.

    Args:
        data: Complete Ethernet frame

    Returns:
        RTFrame if valid PROFINET frame, None otherwise
    """
    if len(data) < 18:  # 14 (eth) + 4 (min RT)
        return None

    parsed_eth = EtherTypeStruct.parse(data[12:14])
    if parsed_eth.ethertype != ETHERTYPE_PROFINET:
        return None

    try:
        return RTFrame.from_bytes(data[14:])
    except ValueError:
        return None
