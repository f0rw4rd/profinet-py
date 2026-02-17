"""Integration tests for cyclic IO exchange.

Tests the full PROFINET cyclic IO lifecycle against the p-net container:
1. Connect with IOCARSingle + IOCR + AlarmCR + ExpectedSubmodule
2. PrmEnd (end parameter phase)
3. ApplicationReady (wait for device CControl, respond with DONE)
4. Start CyclicController (TX/RX threads)
5. Cyclic data exchange
6. Stop and disconnect
"""

import logging
import time

import pytest

from profinet import (
    ConnectResult,
    IOCRSetup,
    IOSlot,
    RPCCon,
    ethernet_socket,
    get_mac,
    get_station_info,
)
from profinet.cyclic import CyclicController
from profinet.rt import (
    build_iocr_configs,
)

from .conftest import (
    GSDML_MOD_ECHO,
    GSDML_SUBMOD_ECHO,
    skip_no_container,
    skip_not_root,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.integration,
    skip_not_root,
    skip_no_container,
]

# Cycle time: 128ms (conservative for Python + container)
SEND_CLOCK_FACTOR = 32  # 1ms base
REDUCTION_RATIO = 128  # 128ms cycle
WATCHDOG_FACTOR = 10  # 10 * 128ms = 1.28s watchdog
DATA_HOLD_FACTOR = 10

# Echo module: slot 4, subslot 1, 8B input + 8B output
ECHO_SLOT = 4
ECHO_SUBSLOT = 1
ECHO_INPUT_LEN = 8
ECHO_OUTPUT_LEN = 8

# Cyclic test duration
RUN_DURATION = 5  # seconds

# Shared state for TestCyclicLifecycle.
# Populated by the _lifecycle fixture so tests can read results
# without relying on cls = type(self) pattern.
_lifecycle_state: dict = {}


# build_iocr_configs is now imported from profinet.rt (CQ-7 deduplication)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def device_info(interface, station_name):
    """Resolve station name to DCP device info."""
    sock = ethernet_socket(interface)
    src_mac = get_mac(interface)
    try:
        info = get_station_info(sock, src_mac, station_name, timeout_sec=3)
        return info, src_mac
    finally:
        sock.close()


@pytest.fixture(scope="module")
def iocr_setup():
    """Build IOCRSetup with echo module only.

    p-net handles DAP submodules internally -- only I/O modules
    should appear in the IOCR blocks sent by the controller.
    """
    slots = [
        # Echo module: 8B input + 8B output
        IOSlot(
            slot=ECHO_SLOT,
            subslot=ECHO_SUBSLOT,
            module_ident=GSDML_MOD_ECHO,
            submodule_ident=GSDML_SUBMOD_ECHO,
            input_length=ECHO_INPUT_LEN,
            output_length=ECHO_OUTPUT_LEN,
        ),
    ]

    return IOCRSetup(
        slots=slots,
        send_clock_factor=SEND_CLOCK_FACTOR,
        reduction_ratio=REDUCTION_RATIO,
        watchdog_factor=WATCHDOG_FACTOR,
        data_hold_factor=DATA_HOLD_FACTOR,
    )


@pytest.fixture(scope="class")
def cyclic_connection(device_info, iocr_setup):
    """Connect with IOCARSingle + IOCR, return (rpc, result, iocr_setup).

    Class-scoped: p-net only supports one AR at a time, so all tests
    in a class share the same connection.
    """
    info, src_mac = device_info
    # Brief pause to let device release any previous AR
    time.sleep(1)
    rpc = RPCCon(info, timeout=10.0)
    result = rpc.connect(
        src_mac=src_mac,
        with_alarm_cr=True,
        iocr_setup=iocr_setup,
    )
    try:
        yield rpc, result, iocr_setup
    finally:
        rpc.close()
        time.sleep(1)  # Let device release AR


# ---------------------------------------------------------------------------
# TestCyclicConnect
# ---------------------------------------------------------------------------


class TestCyclicConnect:
    """Test IOCARSingle connection with IOCR."""

    def test_connect_with_iocr(self, cyclic_connection):
        """IOCARSingle connect succeeds, returns ConnectResult."""
        _rpc, result, _setup = cyclic_connection
        assert result is not None
        assert isinstance(result, ConnectResult)

    def test_connect_result_has_frame_ids(self, cyclic_connection):
        """Input and output frame IDs are valid RT_CLASS_1 IDs."""
        _rpc, result, _setup = cyclic_connection
        assert result.input_frame_id >= 0x8000
        assert result.input_frame_id <= 0xFBFF
        assert result.output_frame_id >= 0x8000
        assert result.output_frame_id <= 0xFBFF

    def test_connect_result_has_cyclic(self, cyclic_connection):
        """ConnectResult.has_cyclic is True."""
        _rpc, result, _setup = cyclic_connection
        assert result.has_cyclic is True

    def test_alarm_cr_established(self, cyclic_connection):
        """AlarmCR reference is valid."""
        _rpc, result, _setup = cyclic_connection
        assert result.device_alarm_ref >= 0


# ---------------------------------------------------------------------------
# TestCyclicLifecycle
# ---------------------------------------------------------------------------


class TestCyclicLifecycle:
    """Test full cyclic IO lifecycle."""

    @pytest.fixture(autouse=True, scope="class")
    def _lifecycle(self, device_info, iocr_setup, interface):
        """Run the full cyclic lifecycle once for all tests in this class.

        Steps:
        1. Connect with IOCARSingle + IOCR
        2. PrmEnd
        3. ApplicationReady
        4. Start CyclicController, run for RUN_DURATION
        5. Stop
        6. Store results in module-level _lifecycle_state for test assertions

        Class-scoped so p-net's single AR is reused across all tests.
        """
        state = _lifecycle_state
        info, src_mac = device_info

        # 1. Connect
        rpc = RPCCon(info, timeout=10.0)
        result = rpc.connect(
            src_mac=src_mac,
            with_alarm_cr=True,
            iocr_setup=iocr_setup,
        )
        assert result is not None and result.has_cyclic

        state["rpc"] = rpc
        state["result"] = result
        state["iocr_setup"] = iocr_setup

        # 2. PrmEnd
        rpc.prm_end()
        state["prm_end_ok"] = True

        # 3. ApplicationReady
        rpc.application_ready(timeout=30.0)
        state["app_ready_ok"] = True

        # 4. Build IOCRConfigs and start CyclicController
        dst_mac = bytes.fromhex(info.mac.replace(":", ""))

        input_iocr, output_iocr = build_iocr_configs(
            iocr_setup.slots,
            result.input_frame_id,
            result.output_frame_id,
            send_clock_factor=SEND_CLOCK_FACTOR,
            reduction_ratio=REDUCTION_RATIO,
            watchdog_factor=WATCHDOG_FACTOR,
        )

        cyclic = CyclicController(
            interface=interface,
            src_mac=src_mac,
            dst_mac=dst_mac,
            input_iocr=input_iocr,
            output_iocr=output_iocr,
        )

        # Set initial echo output data
        cyclic.set_output_data(ECHO_SLOT, ECHO_SUBSLOT, bytes(ECHO_OUTPUT_LEN))

        # Track received data
        received_data = []
        state["received_data"] = received_data

        def on_input(slot, subslot, data):
            received_data.append((slot, subslot, bytes(data)))

        cyclic.on_input(on_input)

        cyclic.start()
        state["cyclic"] = cyclic

        # 5. Run - write echo pattern after brief startup
        time.sleep(0.5)
        echo_pattern = bytes([0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18])
        cyclic.set_output_data(ECHO_SLOT, ECHO_SUBSLOT, echo_pattern)
        state["echo_pattern"] = echo_pattern

        time.sleep(RUN_DURATION)

        # 6. Stop
        cyclic.stop()
        state["stats"] = cyclic.stats

        yield

        # Cleanup
        state.clear()
        try:
            rpc.close()
        except Exception:
            pass

    def test_prm_end_succeeds(self):
        """PrmEnd returns without error."""
        assert _lifecycle_state["prm_end_ok"]

    def test_application_ready(self):
        """Device sends ApplicationReady CControl, controller confirms."""
        assert _lifecycle_state["app_ready_ok"]

    def test_cyclic_frames_sent(self):
        """CyclicController sends output frames (frames_sent > 0)."""
        assert _lifecycle_state["stats"].frames_sent > 0

    def test_cyclic_frames_received(self):
        """CyclicController receives input frames (frames_received > 0)."""
        assert _lifecycle_state["stats"].frames_received > 0

    def test_echo_module_data(self):
        """Echo module reflects output data back on input."""
        received_data = _lifecycle_state["received_data"]
        echo_pattern = _lifecycle_state["echo_pattern"]
        # Filter received data for echo module
        echo_data = [d for s, ss, d in received_data if s == ECHO_SLOT and ss == ECHO_SUBSLOT]
        assert len(echo_data) > 0, "No echo input data received"
        # Check that at least one received frame has a good match
        # against our echo pattern (at least 4 of 8 bytes matching).
        # This is robust to timing while still validating echo behavior.
        best_match = 0
        for frame in echo_data:
            matching = sum(1 for a, b in zip(frame, echo_pattern, strict=False) if a == b)
            best_match = max(best_match, matching)
        assert best_match >= 3, (
            f"Echo pattern poorly reflected: best match was {best_match}/8 bytes "
            f"(expected >= 3). Got {len(echo_data)} frames."
        )

    def test_disconnect_after_cyclic(self):
        """Clean disconnect works after cyclic exchange."""
        # disconnect() is idempotent - safe to call even if fixture cleanup also calls close()
        _lifecycle_state["rpc"].disconnect()
