"""
PROFINET Cyclic IO Controller.

Provides RT_CLASS_1 cyclic data exchange with PROFINET devices:
- Periodic output frame transmission to device
- Input frame reception from device
- Explicit state machine (IDLE -> RUNNING -> FAULT -> STOPPED)
- Double-buffered output data for minimal lock contention
- Per-cycle frame validation and sequence tracking
- Watchdog timeout detection with state transitions
- IOCS handling for input acknowledgment
- Graceful stop with DataStatus RUN->STOP transition
- Separate TX/RX sockets to eliminate contention
- Statistics tracking

Per IEC 61158-6-10:
- Uses EtherType 0x8892
- Frame IDs 0xC000-0xFBFF for RT_CLASS_1

WARNING: EXPERIMENTAL - NOT TESTED WITH REAL DEVICES
=====================================================
This module has NOT been tested with real PROFINET devices.
The cyclic IO exchange may not work correctly. Use at your
own risk. Contributions and test reports are welcome.

WARNING: Python Timing Limitations
==================================
Due to Python's Global Interpreter Lock (GIL) and OS scheduling jitter,
reliable cyclic timing is LIMITED in pure Python:

- MINIMUM practical cycle time: 8ms (may have jitter under load)
- RECOMMENDED cycle time: 32ms or higher for reliable operation
- Sub-millisecond timing: NOT POSSIBLE in Python

For faster cycle times, use:
- C/C++ with real-time OS (PREEMPT_RT Linux)
- Hardware-based PROFINET controllers
- FPGA/ASIC implementations

RT_CLASS_3 (IRT/isochronous) requires hardware support
and is not achievable in pure Python.
"""

from __future__ import annotations

import enum
import logging
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from .rt import (
    _ETHERTYPE_PROFINET_BYTES,
    DATA_STATUS_PROVIDER_RUN,
    DATA_STATUS_STATE,
    DATA_STATUS_STATION_OK,
    DATA_STATUS_VALID,
    ETHERTYPE_PROFINET,
    IOXS_BAD,
    IOXS_DATA_STATE_GOOD,
    IOXS_GOOD,
    VLAN_TAG_RT,
    CyclicDataBuilder,
    EtherTypeStruct,
    IOCRConfig,
    RTFrame,
)
from .util import ethernet_socket as _ethernet_socket
from .util import skip_vlan_tags

logger = logging.getLogger(__name__)


class CyclicState(enum.Enum):
    """State machine for cyclic controller.

    State transitions::

        IDLE -> STARTING -> RUNNING -> STOPPING -> STOPPED
                               |                      ^
                               +-> FAULT -------------+
    """

    IDLE = "idle"
    """Initial state, not yet started."""

    STARTING = "starting"
    """Sockets created, threads launching."""

    RUNNING = "running"
    """Active cyclic data exchange."""

    STOPPING = "stopping"
    """Graceful shutdown in progress (sending STOP frames)."""

    STOPPED = "stopped"
    """Fully stopped, threads joined."""

    FAULT = "fault"
    """Communication failure (e.g., consecutive watchdog timeouts)."""


@dataclass
class CyclicStats:
    """Statistics for cyclic communication.

    Tracks frame counts, timing, and errors.

    Note: These counters are mutated from multiple threads (TX and RX)
    without explicit synchronization. Under CPython's GIL, individual
    integer increments are atomic, and these are advisory statistics
    where occasional stale reads are acceptable. No lock is needed.
    """

    frames_sent: int = 0
    """Total output frames transmitted."""

    frames_received: int = 0
    """Total input frames received."""

    frames_missed: int = 0
    """Number of watchdog timeouts (missed frames)."""

    frames_invalid: int = 0
    """Number of received frames with invalid status."""

    frames_duplicate: int = 0
    """Number of duplicate frames (same cycle counter received twice)."""

    frames_out_of_order: int = 0
    """Number of frames received out of expected sequence."""

    last_cycle_time_us: int = 0
    """Actual cycle time of last transmission (microseconds)."""

    max_jitter_us: int = 0
    """Maximum observed jitter (deviation from target cycle)."""

    min_cycle_time_us: int = 2**31
    """Minimum observed cycle time (microseconds)."""

    max_cycle_time_us: int = 0
    """Maximum observed cycle time (microseconds)."""

    last_receive_time: float = field(default_factory=time.perf_counter)
    """Timestamp of last received frame (time.perf_counter).

    Initialized to current time to avoid spurious watchdog timeout
    on first check (BUG-7: perf_counter() returns time since boot,
    so 0.0 would always look like a timeout).
    """

    consecutive_timeouts: int = 0
    """Current streak of consecutive watchdog timeouts."""

    _cycle_time_sum_us: int = 0
    _cycle_count: int = 0

    @property
    def avg_cycle_time_us(self) -> int:
        """Average cycle time (microseconds)."""
        return self._cycle_time_sum_us // self._cycle_count if self._cycle_count else 0

    def reset(self) -> None:
        """Reset all statistics.

        Resets counters to zero and sets last_receive_time to current
        time to avoid spurious watchdog timeout on restart.
        """
        self.frames_sent = 0
        self.frames_received = 0
        self.frames_missed = 0
        self.frames_invalid = 0
        self.frames_duplicate = 0
        self.frames_out_of_order = 0
        self.last_cycle_time_us = 0
        self.max_jitter_us = 0
        self.min_cycle_time_us = 2**31
        self.max_cycle_time_us = 0
        self.last_receive_time = time.perf_counter()
        self.consecutive_timeouts = 0
        self._cycle_time_sum_us = 0
        self._cycle_count = 0


# Minimum recommended cycle time for Python
PYTHON_MIN_CYCLE_MS = 8
PYTHON_RECOMMENDED_CYCLE_MS = 32

# Default number of consecutive watchdog timeouts before FAULT
DEFAULT_MAX_CONSECUTIVE_TIMEOUTS = 3

# Number of STOP frames to send during graceful shutdown
STOP_FRAME_COUNT = 3


class CyclicController:
    """RT_CLASS_1 cyclic data exchange controller.

    Manages bidirectional cyclic IO communication with a PROFINET device:
    - TX thread sends output data to device at configured rate
    - RX thread receives and processes input data from device
    - Explicit state machine tracks controller lifecycle
    - Double-buffered output for minimal lock contention
    - Cycle counter tracking detects gaps, duplicates, out-of-order
    - Watchdog escalates to FAULT after consecutive timeouts
    - IOCS bytes acknowledge received input data
    - Graceful stop sends STOP frames before closing

    Example:
        >>> controller = CyclicController(
        ...     interface="eth0",
        ...     src_mac=controller_mac,
        ...     dst_mac=device_mac,
        ...     input_iocr=input_config,
        ...     output_iocr=output_config,
        ... )
        >>> controller.on_input(lambda s, ss, d: print(f"Data from {s}:{ss}"))
        >>> controller.start()
        >>> controller.set_output_data(1, 1, b"\\x01\\x02\\x03\\x04")
        >>> # ... let it run ...
        >>> controller.stop()

    Warning:
        Python timing limitations apply! Recommended cycle times:
        - 32ms+: Reliable on all systems
        - 8-16ms: Works on most systems with low load
        - <8ms: NOT RECOMMENDED - expect jitter and missed frames
        - <1ms: NOT POSSIBLE in Python
    """

    def __init__(
        self,
        interface: str,
        src_mac: bytes,
        dst_mac: bytes,
        input_iocr: IOCRConfig,
        output_iocr: IOCRConfig,
        max_consecutive_timeouts: int = DEFAULT_MAX_CONSECUTIVE_TIMEOUTS,
    ):
        """Initialize cyclic controller.

        Args:
            interface: Network interface name (e.g., "eth0")
            src_mac: Controller MAC address (6 bytes)
            dst_mac: Device MAC address (6 bytes)
            input_iocr: IOCR config for input data (device -> controller)
            output_iocr: IOCR config for output data (controller -> device)
            max_consecutive_timeouts: Watchdog timeouts before FAULT state
                (0 = never enter FAULT)

        Warns:
            If cycle time is below recommended minimum for Python.
        """
        if max_consecutive_timeouts < 0:
            raise ValueError(
                f"max_consecutive_timeouts must be >= 0, got {max_consecutive_timeouts}"
            )

        self.interface = interface
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.input_iocr = input_iocr
        self.output_iocr = output_iocr
        self.max_consecutive_timeouts = max_consecutive_timeouts

        # State machine
        self._state = CyclicState.IDLE
        self._state_lock = threading.Lock()

        self._running = False
        self._tx_thread: Optional[threading.Thread] = None
        self._rx_thread: Optional[threading.Thread] = None
        self._tx_sock: Optional[socket.socket] = None
        self._rx_sock: Optional[socket.socket] = None

        # Cycle state
        self._cycle_counter = 0
        self._output_builder = CyclicDataBuilder(output_iocr)
        self._input_data: Dict[Tuple[int, int], bytes] = {}
        # Last provider status (IOPS) the device sent per submodule. Payload
        # bytes are only meaningful while the matching IOPS reports GOOD.
        self._input_status: Dict[Tuple[int, int], int] = {}
        self._input_lock = threading.Lock()

        # Cycle counter tracking for RX
        # Per IEC 61158-6-10, cycle counter increments by
        # send_clock_factor * reduction_ratio per frame
        self._last_rx_cycle_counter: Optional[int] = None
        self._rx_counter_step = input_iocr.send_clock_factor * input_iocr.reduction_ratio

        # TX cycle counter step (PROTO-1: must match SCF * RR, not +1)
        self._tx_counter_step = output_iocr.send_clock_factor * output_iocr.reduction_ratio

        # Check and warn about cycle time
        self._check_cycle_time()

        # Initialize provider and consumer status to good before the first
        # transmitted frame. Some IO devices do not start their input provider
        # until the controller reports that it is consuming input data.
        self._output_builder.set_all_iops(IOXS_GOOD)
        self._output_builder.set_all_iocs(IOXS_GOOD)
        # Tracks the watchdog-driven IOCS state so the RX/timeout paths only
        # rewrite the buffer on transitions (both run on the RX thread).
        self._iocs_good = True

        # Callbacks
        self._on_input_data: Optional[Callable[[int, int, bytes], None]] = None
        self._on_input_status: Optional[Callable[[int, int, int], None]] = None
        self._on_timeout: Optional[Callable[[], None]] = None
        self._on_error: Optional[Callable[[str], None]] = None
        self._on_state_change: Optional[Callable[[CyclicState, CyclicState], None]] = None

        # Statistics
        self.stats = CyclicStats()

    def _check_cycle_time(self) -> None:
        """Check cycle time and log warnings if too fast for Python."""
        cycle_ms = self.output_iocr.cycle_time_ms

        if cycle_ms < 1:
            raise ValueError(
                f"Cycle time {cycle_ms:.2f}ms is below 1ms — not achievable in "
                f"Python. Use a C/FPGA-based controller for sub-millisecond cycles."
            )
        elif cycle_ms < PYTHON_MIN_CYCLE_MS:
            import warnings

            warnings.warn(
                f"Cycle time {cycle_ms:.0f}ms is below the recommended "
                f"{PYTHON_MIN_CYCLE_MS}ms minimum for Python. "
                f"Expect jitter and missed frames. "
                f"Use {PYTHON_RECOMMENDED_CYCLE_MS}ms+ for reliable operation.",
                stacklevel=3,
            )

    # =========================================================================
    # State machine
    # =========================================================================

    @property
    def state(self) -> CyclicState:
        """Current controller state."""
        return self._state

    def _transition(self, new_state: CyclicState) -> None:
        """Transition to a new state with logging.

        Args:
            new_state: Target state
        """
        with self._state_lock:
            old = self._state
            if old == new_state:
                return
            self._state = new_state
        logger.info(f"Cyclic state: {old.value} -> {new_state.value}")
        if self._on_state_change:
            try:
                self._on_state_change(old, new_state)
            except Exception as e:
                logger.error(f"State change callback error: {e}")

    # =========================================================================
    # Public API
    # =========================================================================

    def set_output_data(self, slot: int, subslot: int, data: bytes) -> None:
        """Set output data for next cycle.

        Thread-safe - can be called from any thread.
        Uses double-buffered writes (no contention with TX thread).

        Args:
            slot: Slot number
            subslot: Subslot number
            data: Process data bytes

        Raises:
            RuntimeError: If controller is in FAULT or STOPPED state
        """
        if self._state in (CyclicState.FAULT, CyclicState.STOPPED):
            raise RuntimeError(f"Cannot set output data in {self._state.value} state")
        self._output_builder.set_data(slot, subslot, data)
        self._output_builder.set_iops(slot, subslot, IOXS_GOOD)

    def get_input_data(self, slot: int, subslot: int, allow_bad: bool = False) -> Optional[bytes]:
        """Get latest input data from device.

        Thread-safe - can be called from any thread.

        Data whose IOPS is BAD must not be used by the application: the device
        is telling us the payload is not valid (module pulled, sensor faulted),
        and the bytes it keeps sending are stale. Such data is withheld unless
        allow_bad is set. Use get_input_status() to inspect the raw IOPS.

        Args:
            slot: Slot number
            subslot: Subslot number
            allow_bad: Return the payload even when the device marked IOPS BAD

        Returns:
            Latest input data bytes, or None if not received or IOPS is BAD
        """
        with self._input_lock:
            if not allow_bad and not self._is_input_good(slot, subslot):
                return None
            return self._input_data.get((slot, subslot))

    def get_input_status(self, slot: int, subslot: int) -> Optional[int]:
        """Get the provider status (IOPS) the device sent for a submodule.

        Args:
            slot: Slot number
            subslot: Subslot number

        Returns:
            Raw IOPS byte (0x80 = GOOD), or None if nothing received yet
        """
        with self._input_lock:
            return self._input_status.get((slot, subslot))

    def is_input_good(self, slot: int, subslot: int) -> bool:
        """Whether the device currently reports GOOD provider status.

        Args:
            slot: Slot number
            subslot: Subslot number

        Returns:
            True if the last received IOPS for this submodule was GOOD
        """
        with self._input_lock:
            return self._is_input_good(slot, subslot)

    def _is_input_good(self, slot: int, subslot: int) -> bool:
        """IOPS check without taking the lock. Caller must hold _input_lock."""
        status = self._input_status.get((slot, subslot))
        return status is not None and bool(status & IOXS_DATA_STATE_GOOD)

    def on_input(self, callback: Callable[[int, int, bytes], None]) -> None:
        """Register callback for input data updates.

        Callback is invoked from RX thread for each received data update.

        Args:
            callback: Function(slot, subslot, data) called on input
        """
        self._on_input_data = callback

    def on_input_status(self, callback: Callable[[int, int, int], None]) -> None:
        """Register callback for provider status (IOPS) changes.

        Invoked from the RX thread whenever a submodule's IOPS transitions
        between GOOD and BAD, which is how a device signals that its input data
        has become invalid (module pulled, sensor faulted) without dropping the
        AR. The frame keeps arriving with stale payload, so this is the only
        notification the application gets.

        Args:
            callback: Function(slot, subslot, iops) called on IOPS transitions
        """
        self._on_input_status = callback

    def on_timeout(self, callback: Callable[[], None]) -> None:
        """Register callback for watchdog timeout.

        Called when no input frame received within watchdog time.

        Args:
            callback: Function called on timeout
        """
        self._on_timeout = callback

    def on_error(self, callback: Callable[[str], None]) -> None:
        """Register callback for communication errors.

        Args:
            callback: Function(error_message) called on error
        """
        self._on_error = callback

    def on_state_change(self, callback: Callable[[CyclicState, CyclicState], None]) -> None:
        """Register callback for state transitions.

        Args:
            callback: Function(old_state, new_state) called on transition
        """
        self._on_state_change = callback

    def start(self) -> None:
        """Start cyclic data exchange.

        Creates separate TX/RX sockets and spawns threads.

        Raises:
            RuntimeError: If already running or in invalid state
        """
        if self._state not in (CyclicState.IDLE, CyclicState.STOPPED, CyclicState.FAULT):
            raise RuntimeError(f"Cannot start from {self._state.value} state")

        self._transition(CyclicState.STARTING)
        self._running = True
        self.stats.reset()
        self._last_rx_cycle_counter = None

        # Create separate TX and RX sockets. The RX socket binds ETH_P_ALL:
        # a socket bound to 0x8892 never sees VLAN-tagged frames unless the
        # NIC strips the tag, and devices commonly send priority-tagged RT.
        self._tx_sock = self._create_raw_socket(timeout=None)
        self._rx_sock = self._create_raw_socket(timeout=0.001, ethertype=None)

        # Swap initial data into send buffer
        self._output_builder.swap()

        # Start TX thread
        self._tx_thread = threading.Thread(
            target=self._tx_loop,
            daemon=True,
            name=f"CyclicTX-{self.interface}",
        )
        self._tx_thread.start()

        # Start RX thread
        self._rx_thread = threading.Thread(
            target=self._rx_loop,
            daemon=True,
            name=f"CyclicRX-{self.interface}",
        )
        self._rx_thread.start()

        self._transition(CyclicState.RUNNING)
        logger.info(
            f"Cyclic controller started on {self.interface} "
            f"(cycle={self.output_iocr.cycle_time_ms:.1f}ms)"
        )

    def stop(self) -> None:
        """Stop cyclic exchange gracefully.

        Sends STOP frames (DataStatus with ProviderRun cleared) to let the
        device enter safe state, then stops threads and closes sockets.

        Order of operations (BUG-1 fix):
        1. Set _running = False so TX loop exits
        2. Wait for TX thread to finish (no more concurrent socket access)
        3. Send STOP frames on the now-uncontended TX socket
        4. Close RX socket to unblock recv, wait for RX thread
        5. Close TX socket and clean up
        """
        if not self._running:
            return

        self._transition(CyclicState.STOPPING)

        # 1. Signal threads to exit BEFORE sending stop frames
        self._running = False

        # 2. Wait for TX thread to finish first -- ensures no concurrent
        #    socket access or cycle counter mutation during stop frames
        if self._tx_thread and self._tx_thread.is_alive():
            self._tx_thread.join(timeout=2.0)

        # 3. Send STOP frames after TX thread has exited
        self._send_stop_frames()

        # 4. Close RX socket to unblock recv
        if self._rx_sock:
            try:
                self._rx_sock.close()
            except OSError:
                pass

        # Wait for RX thread
        if self._rx_thread and self._rx_thread.is_alive():
            self._rx_thread.join(timeout=2.0)

        # 5. Close TX socket after stop frames sent
        if self._tx_sock:
            try:
                self._tx_sock.close()
            except OSError:
                pass

        self._tx_sock = None
        self._rx_sock = None
        self._tx_thread = None
        self._rx_thread = None

        self._transition(CyclicState.STOPPED)
        logger.info(
            f"Cyclic controller stopped "
            f"(sent={self.stats.frames_sent}, recv={self.stats.frames_received})"
        )

    @property
    def is_running(self) -> bool:
        """True if controller is currently running."""
        return self._state == CyclicState.RUNNING

    # =========================================================================
    # Socket creation
    # =========================================================================

    def _create_raw_socket(
        self, timeout: Optional[float] = None, ethertype: Optional[int] = ETHERTYPE_PROFINET
    ):
        """Create raw Ethernet socket.

        Args:
            timeout: Socket timeout (None for blocking, float for timeout)
            ethertype: Bind protocol; None binds ETH_P_ALL so VLAN-tagged
                frames are delivered too

        Returns:
            Configured socket

        Raises:
            PermissionError: If raw socket requires root/admin privileges
        """
        try:
            sock = _ethernet_socket(self.interface, ethertype)
        except PermissionError as e:
            raise PermissionError(f"Raw socket requires root/admin privileges: {e}") from e

        if timeout is not None:
            sock.settimeout(timeout)
        return sock

    # =========================================================================
    # TX path
    # =========================================================================

    def _tx_cycle(self) -> None:
        """Swap the output buffer and transmit one frame.

        Runs every cycle, including in FAULT: if the controller stops
        sending, the device's Data Hold Timer expires and it aborts the
        whole AR, so input frames can never resume and FAULT recovery
        becomes unreachable. IOCS is already BAD in FAULT.
        """
        self._output_builder.swap()
        self._send_output_frame()
        self.stats.frames_sent += 1

    def _tx_loop(self) -> None:
        """Transmit loop - sends output frames at cycle rate."""
        cycle_time_s = self.output_iocr.cycle_time_us / 1_000_000
        next_send = time.perf_counter()
        last_send = next_send
        first_frame = True

        logger.debug(f"TX thread started, cycle={cycle_time_s * 1000:.2f}ms")

        while self._running:
            now = time.perf_counter()

            if now >= next_send:
                self._tx_cycle()

                if first_frame:
                    first_frame = False
                else:
                    # Calculate actual cycle time and jitter (skip first frame)
                    actual_us = int((now - last_send) * 1_000_000)
                    self.stats.last_cycle_time_us = actual_us
                    jitter = abs(actual_us - self.output_iocr.cycle_time_us)
                    if jitter > self.stats.max_jitter_us:
                        self.stats.max_jitter_us = jitter
                    self.stats.min_cycle_time_us = min(self.stats.min_cycle_time_us, actual_us)
                    self.stats.max_cycle_time_us = max(self.stats.max_cycle_time_us, actual_us)
                    self.stats._cycle_time_sum_us += actual_us
                    self.stats._cycle_count += 1

                last_send = now

                # Calculate next send time
                next_send += cycle_time_s

                # If we're behind, catch up
                if next_send < now:
                    missed = int((now - next_send) / cycle_time_s)
                    next_send = now + cycle_time_s
                    if missed > 0:
                        logger.warning(f"TX: missed {missed} cycles")

            # Sleep until next cycle
            sleep_time = next_send - time.perf_counter() - 0.0001
            if sleep_time > 0:
                time.sleep(sleep_time)

        logger.debug("TX thread stopped")

    def _send_output_frame(self, data_status: Optional[int] = None) -> None:
        """Build and send output RT frame.

        Args:
            data_status: Override data status byte. If None, uses normal
                         RUN status.
        """
        self._cycle_counter = (self._cycle_counter + self._tx_counter_step) & 0xFFFF

        # Build payload from send buffer (lock-free after swap)
        payload = self._output_builder.build()

        if data_status is None:
            data_status = (
                DATA_STATUS_VALID
                | DATA_STATUS_PROVIDER_RUN
                | DATA_STATUS_STATION_OK
                | DATA_STATUS_STATE
            )

        frame = RTFrame(
            frame_id=self.output_iocr.frame_id,
            cycle_counter=self._cycle_counter,
            data_status=data_status,
            transfer_status=0x00,
            payload=payload,
        )

        # Build Ethernet frame
        eth_frame = (
            self.dst_mac + self.src_mac + VLAN_TAG_RT + _ETHERTYPE_PROFINET_BYTES + frame.to_bytes()
        )

        try:
            self._tx_sock.send(eth_frame)
        except Exception as e:
            logger.error(f"TX error: {e}")
            if self._on_error:
                self._on_error(f"TX error: {e}")

    def _send_stop_frames(self) -> None:
        """Send frames with ProviderRun=STOP before shutting down.

        Gives the device time to detect the stop and enter safe state.
        """
        if not self._tx_sock:
            return

        stop_status = (
            DATA_STATUS_VALID | DATA_STATUS_STATION_OK | DATA_STATUS_STATE
            # DATA_STATUS_PROVIDER_RUN is NOT set = STOP
        )

        cycle_time_s = self.output_iocr.cycle_time_us / 1_000_000

        for i in range(STOP_FRAME_COUNT):
            try:
                self._output_builder.swap()
                self._send_output_frame(data_status=stop_status)
                self.stats.frames_sent += 1
            except Exception as e:
                logger.debug(f"Stop frame {i} send error: {e}")
                break
            if i < STOP_FRAME_COUNT - 1:
                time.sleep(cycle_time_s)

    # =========================================================================
    # RX path
    # =========================================================================

    def _rx_loop(self) -> None:
        """Receive loop - processes input frames from device."""
        watchdog_s = self.input_iocr.watchdog_time_us / 1_000_000
        self.stats.last_receive_time = time.perf_counter()

        logger.debug(f"RX thread started, watchdog={watchdog_s * 1000:.1f}ms")

        while self._running:
            try:
                data = self._rx_sock.recv(4096)
                self._process_input_frame(data)

            except TimeoutError:
                # Check watchdog
                elapsed = time.perf_counter() - self.stats.last_receive_time
                if elapsed > watchdog_s:
                    self._handle_watchdog_timeout()
                    # Reset timer
                    self.stats.last_receive_time = time.perf_counter()
                continue

            except OSError:
                # Socket closed
                if self._running:
                    logger.error("RX: Socket closed unexpectedly")
                break

            except Exception as e:
                logger.error(f"RX error: {e}")
                if self._on_error:
                    self._on_error(f"RX error: {e}")

        logger.debug("RX thread stopped")

    def _handle_watchdog_timeout(self) -> None:
        """Handle a watchdog timeout event.

        Increments counters, sets IOCS to BAD, and transitions to
        FAULT after max_consecutive_timeouts.
        """
        self.stats.frames_missed += 1
        self.stats.consecutive_timeouts += 1

        # Set IOCS to BAD only when watchdog faulting is enabled. With
        # max_consecutive_timeouts=0 the watchdog is monitoring-only; keep
        # consumer status GOOD so transient RX gaps do not make the device drop
        # an otherwise active output relationship.
        if self.max_consecutive_timeouts > 0 and self._iocs_good:
            self._output_builder.set_all_iocs(IOXS_BAD)
            self._iocs_good = False

        if self._on_timeout:
            try:
                self._on_timeout()
            except Exception as e:
                logger.error(f"Timeout callback error: {e}")

        # Check for FAULT transition
        if (
            self.max_consecutive_timeouts > 0
            and self.stats.consecutive_timeouts >= self.max_consecutive_timeouts
            and self._state == CyclicState.RUNNING
        ):
            logger.error(
                f"Watchdog: {self.stats.consecutive_timeouts} consecutive "
                f"timeouts, entering FAULT state"
            )
            self._transition(CyclicState.FAULT)
            if self._on_error:
                self._on_error(
                    f"Communication lost: {self.stats.consecutive_timeouts} "
                    f"consecutive watchdog timeouts"
                )

    def _process_input_frame(self, data: bytes) -> None:
        """Parse and process received RT frame.

        Args:
            data: Raw Ethernet frame
        """
        if len(data) < 18:
            return

        # Parse Ethernet header; devices may send 802.1Q priority-tagged frames
        src_mac = data[6:12]
        eth_offset = skip_vlan_tags(data)
        ethertype = EtherTypeStruct.parse(data[eth_offset : eth_offset + 2]).ethertype

        if ethertype != ETHERTYPE_PROFINET:
            return

        # Filter by device MAC
        if src_mac != self.dst_mac:
            return

        try:
            frame = RTFrame.from_bytes(data[eth_offset + 2 :])
        except ValueError:
            return

        # Check frame ID matches our input IOCR
        if frame.frame_id != self.input_iocr.frame_id:
            return

        # Update receive time and reset consecutive timeout counter
        self.stats.last_receive_time = time.perf_counter()
        self.stats.frames_received += 1
        self.stats.consecutive_timeouts = 0

        # If in FAULT and we got a frame, recover to RUNNING
        if self._state == CyclicState.FAULT:
            logger.info("Watchdog: frame received, recovering from FAULT")
            self._transition(CyclicState.RUNNING)

        # Cycle counter tracking
        self._track_cycle_counter(frame.cycle_counter)

        # Check validity. TransferStatus != 0 means the provider flagged a
        # transfer problem; conformant consumers discard such frames.
        if not frame.is_valid or frame.transfer_status != 0:
            self.stats.frames_invalid += 1
            return

        # Set IOCS to GOOD - we received valid input data. Only rewrite the
        # buffer on a BAD->GOOD transition; set_all_iocs dirties the whole
        # send buffer and this runs for every received frame.
        if not self._iocs_good:
            self._output_builder.set_all_iocs(IOXS_GOOD)
            self._iocs_good = True

        # Extract data per IO object. Each submodule's payload is followed by
        # its IOPS byte; the device sets it BAD to disown the data it is still
        # sending, so the payload is only usable while IOPS reports GOOD.
        status_events = []
        data_events = []
        with self._input_lock:
            for obj in self.input_iocr.objects:
                if obj.iops_offset >= len(frame.payload):
                    continue
                if obj.frame_offset + obj.data_length > len(frame.payload):
                    continue

                iops = frame.payload[obj.iops_offset]
                key = (obj.slot, obj.subslot)
                was_good = self._is_input_good(obj.slot, obj.subslot)
                is_good = bool(iops & IOXS_DATA_STATE_GOOD)

                self._input_status[key] = iops
                self._input_data[key] = frame.payload[
                    obj.frame_offset : obj.frame_offset + obj.data_length
                ]

                if is_good != was_good:
                    status_events.append((obj.slot, obj.subslot, iops))
                if is_good:
                    data_events.append((obj.slot, obj.subslot, self._input_data[key]))

        # Callbacks run outside the lock: they are application code and must not
        # be able to stall the RX thread's next frame while holding it.
        for slot, subslot, iops in status_events:
            if not iops & IOXS_DATA_STATE_GOOD:
                logger.warning(
                    f"Slot {slot}/{subslot}: device reports IOPS BAD (0x{iops:02X}), "
                    f"input data is no longer valid"
                )
            if self._on_input_status:
                try:
                    self._on_input_status(slot, subslot, iops)
                except Exception as e:
                    logger.error(f"Input status callback error: {e}")

        if self._on_input_data:
            for slot, subslot, obj_data in data_events:
                try:
                    self._on_input_data(slot, subslot, obj_data)
                except Exception as e:
                    logger.error(f"Input callback error: {e}")

    def _track_cycle_counter(self, rx_counter: int) -> None:
        """Track received cycle counter for gap/duplicate detection.

        Per IEC 61158-6-10, the cycle counter increments by
        send_clock_factor * reduction_ratio per frame (not by 1).
        For example, with SCF=32 and RR=32, the step is 1024.

        Args:
            rx_counter: Cycle counter from received frame
        """
        if self._last_rx_cycle_counter is None:
            # First frame - just record
            self._last_rx_cycle_counter = rx_counter
            return

        step = self._rx_counter_step
        expected = (self._last_rx_cycle_counter + step) & 0xFFFF

        if rx_counter == self._last_rx_cycle_counter:
            # Duplicate
            self.stats.frames_duplicate += 1
        elif rx_counter != expected:
            # Gap or out-of-order
            # Calculate forward distance (handles 16-bit wrap)
            forward = (rx_counter - self._last_rx_cycle_counter) & 0xFFFF
            if forward > 0x8000:
                # Counter went backwards = out of order
                self.stats.frames_out_of_order += 1
            else:
                # Gap: count how many frames were skipped
                if step > 0:
                    gap = (forward // step) - 1
                else:
                    gap = 0
                if gap > 0:
                    self.stats.frames_missed += gap
            self._last_rx_cycle_counter = rx_counter
        else:
            # Normal sequential
            self._last_rx_cycle_counter = rx_counter

    # =========================================================================
    # Context manager & repr
    # =========================================================================

    def __enter__(self) -> CyclicController:
        """Context manager entry - start controller."""
        self.start()
        return self

    def __exit__(self, *args) -> None:
        """Context manager exit - stop controller."""
        self.stop()

    def __repr__(self) -> str:
        return (
            f"CyclicController({self.interface}, "
            f"out_id=0x{self.output_iocr.frame_id:04X}, "
            f"in_id=0x{self.input_iocr.frame_id:04X}, "
            f"{self._state.value})"
        )
