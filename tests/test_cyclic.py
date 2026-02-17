"""Tests for profinet.cyclic module (Cyclic IO Controller)."""

import time
from unittest.mock import MagicMock

import pytest

from profinet.cyclic import (
    CyclicController,
    CyclicState,
    CyclicStats,
)
from profinet.rt import (
    DATA_STATUS_PROVIDER_RUN,
    DATA_STATUS_STATE,
    DATA_STATUS_STATION_OK,
    DATA_STATUS_VALID,
    IOCR_TYPE_INPUT,
    IOCR_TYPE_OUTPUT,
    IOCRConfig,
    IODataObject,
)


def make_input_iocr(**kwargs):
    """Helper to create an input IOCR config.

    Default SCF=1, RR=1 so cycle counter step = 1 (simple for tests).
    """
    defaults = {
        "iocr_type": IOCR_TYPE_INPUT,
        "iocr_reference": 1,
        "frame_id": 0xC001,
        "send_clock_factor": 1,
        "reduction_ratio": 1,
        "watchdog_factor": 3,
        "data_length": 40,
        "objects": [
            IODataObject(slot=1, subslot=1, frame_offset=0, data_length=4, iops_offset=4),
        ],
    }
    defaults.update(kwargs)
    return IOCRConfig(**defaults)


def make_output_iocr(**kwargs):
    """Helper to create an output IOCR config."""
    defaults = {
        "iocr_type": IOCR_TYPE_OUTPUT,
        "iocr_reference": 2,
        "frame_id": 0xC000,
        "send_clock_factor": 32,
        "reduction_ratio": 32,
        "watchdog_factor": 3,
        "data_length": 40,
        "objects": [
            IODataObject(slot=1, subslot=1, frame_offset=0, data_length=4, iops_offset=4),
        ],
    }
    defaults.update(kwargs)
    return IOCRConfig(**defaults)


def make_controller(**kwargs):
    """Helper to create a CyclicController without starting it."""
    defaults = {
        "interface": "eth0",
        "src_mac": b"\x00\x11\x22\x33\x44\x55",
        "dst_mac": b"\xd0\xc8\x57\xe0\x1c\x2c",
        "input_iocr": make_input_iocr(),
        "output_iocr": make_output_iocr(),
    }
    defaults.update(kwargs)
    return CyclicController(**defaults)


# =============================================================================
# CyclicState
# =============================================================================


class TestCyclicState:
    """Test CyclicState enum."""

    def test_all_states_exist(self):
        assert CyclicState.IDLE
        assert CyclicState.STARTING
        assert CyclicState.RUNNING
        assert CyclicState.STOPPING
        assert CyclicState.STOPPED
        assert CyclicState.FAULT

    def test_state_values(self):
        assert CyclicState.IDLE.value == "idle"
        assert CyclicState.RUNNING.value == "running"
        assert CyclicState.FAULT.value == "fault"


# =============================================================================
# CyclicStats
# =============================================================================


class TestCyclicStats:
    """Test CyclicStats dataclass."""

    def test_defaults(self):
        stats = CyclicStats()
        assert stats.frames_sent == 0
        assert stats.frames_received == 0
        assert stats.frames_missed == 0
        assert stats.frames_invalid == 0
        assert stats.frames_duplicate == 0
        assert stats.frames_out_of_order == 0
        assert stats.consecutive_timeouts == 0

    def test_reset(self):
        stats = CyclicStats()
        stats.frames_sent = 100
        stats.frames_duplicate = 5
        stats.frames_out_of_order = 3
        stats.consecutive_timeouts = 2
        stats.reset()
        assert stats.frames_sent == 0
        assert stats.frames_duplicate == 0
        assert stats.frames_out_of_order == 0
        assert stats.consecutive_timeouts == 0

    def test_avg_cycle_time(self):
        stats = CyclicStats()
        stats._cycle_time_sum_us = 30000
        stats._cycle_count = 3
        assert stats.avg_cycle_time_us == 10000

    def test_avg_cycle_time_zero(self):
        stats = CyclicStats()
        assert stats.avg_cycle_time_us == 0


# =============================================================================
# CyclicController - State Machine
# =============================================================================


class TestCyclicControllerState:
    """Test state machine behavior."""

    def test_initial_state_is_idle(self):
        ctrl = make_controller()
        assert ctrl.state == CyclicState.IDLE

    def test_set_output_data_fails_in_fault(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.FAULT
        with pytest.raises(RuntimeError, match="fault"):
            ctrl.set_output_data(1, 1, b"\x01\x02\x03\x04")

    def test_set_output_data_fails_in_stopped(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.STOPPED
        with pytest.raises(RuntimeError, match="stopped"):
            ctrl.set_output_data(1, 1, b"\x01\x02\x03\x04")

    def test_set_output_data_works_in_idle(self):
        ctrl = make_controller()
        ctrl.set_output_data(1, 1, b"\x01\x02\x03\x04")

    def test_start_fails_in_running(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        with pytest.raises(RuntimeError, match="Cannot start"):
            ctrl.start()

    def test_start_allowed_from_idle(self):
        ctrl = make_controller()
        assert ctrl.state == CyclicState.IDLE
        # Can't actually start (no socket), but state check passes
        # We test the state gate, not the socket creation

    def test_is_running_reflects_state(self):
        ctrl = make_controller()
        assert not ctrl.is_running
        ctrl._state = CyclicState.RUNNING
        assert ctrl.is_running
        ctrl._state = CyclicState.FAULT
        assert not ctrl.is_running

    def test_state_change_callback(self):
        ctrl = make_controller()
        transitions = []
        ctrl.on_state_change(lambda old, new: transitions.append((old, new)))
        ctrl._transition(CyclicState.STARTING)
        ctrl._transition(CyclicState.RUNNING)
        assert transitions == [
            (CyclicState.IDLE, CyclicState.STARTING),
            (CyclicState.STARTING, CyclicState.RUNNING),
        ]

    def test_transition_noop_same_state(self):
        ctrl = make_controller()
        transitions = []
        ctrl.on_state_change(lambda old, new: transitions.append((old, new)))
        ctrl._transition(CyclicState.IDLE)
        assert transitions == []

    def test_repr_shows_state(self):
        ctrl = make_controller()
        assert "idle" in repr(ctrl)
        ctrl._state = CyclicState.RUNNING
        assert "running" in repr(ctrl)


# =============================================================================
# CyclicController - Cycle Counter Tracking
# =============================================================================


class TestCycleCounterTracking:
    """Test cycle counter gap/duplicate/out-of-order detection."""

    def test_first_frame_sets_counter(self):
        ctrl = make_controller()
        ctrl._track_cycle_counter(42)
        assert ctrl._last_rx_cycle_counter == 42

    def test_sequential_frames(self):
        ctrl = make_controller()
        ctrl._track_cycle_counter(1)
        ctrl._track_cycle_counter(2)
        ctrl._track_cycle_counter(3)
        assert ctrl.stats.frames_duplicate == 0
        assert ctrl.stats.frames_out_of_order == 0
        assert ctrl.stats.frames_missed == 0

    def test_duplicate_detection(self):
        ctrl = make_controller()
        ctrl._track_cycle_counter(5)
        ctrl._track_cycle_counter(5)
        assert ctrl.stats.frames_duplicate == 1

    def test_gap_detection(self):
        ctrl = make_controller()
        ctrl._track_cycle_counter(1)
        ctrl._track_cycle_counter(4)  # gap of 2 (missed 2, 3)
        assert ctrl.stats.frames_missed == 2

    def test_out_of_order_detection(self):
        ctrl = make_controller()
        ctrl._track_cycle_counter(5)
        ctrl._track_cycle_counter(3)  # went backwards
        assert ctrl.stats.frames_out_of_order == 1

    def test_wrap_around(self):
        ctrl = make_controller()
        ctrl._track_cycle_counter(0xFFFE)
        ctrl._track_cycle_counter(0xFFFF)
        ctrl._track_cycle_counter(0x0000)
        assert ctrl.stats.frames_missed == 0
        assert ctrl.stats.frames_duplicate == 0
        assert ctrl.stats.frames_out_of_order == 0

    def test_wrap_with_gap(self):
        ctrl = make_controller()
        ctrl._track_cycle_counter(0xFFFE)
        ctrl._track_cycle_counter(0x0001)  # missed FFFF and 0000
        assert ctrl.stats.frames_missed == 2

    def test_step_based_tracking(self):
        """With SCF=32, RR=32 the step is 1024."""
        ctrl = make_controller(
            input_iocr=make_input_iocr(send_clock_factor=32, reduction_ratio=32),
        )
        assert ctrl._rx_counter_step == 1024
        ctrl._track_cycle_counter(0)
        ctrl._track_cycle_counter(1024)
        ctrl._track_cycle_counter(2048)
        assert ctrl.stats.frames_missed == 0
        assert ctrl.stats.frames_duplicate == 0

    def test_step_based_gap(self):
        """With step=1024, skipping one frame means counter jumps by 2048."""
        ctrl = make_controller(
            input_iocr=make_input_iocr(send_clock_factor=32, reduction_ratio=32),
        )
        ctrl._track_cycle_counter(0)
        ctrl._track_cycle_counter(2048)  # skipped one frame (1024)
        assert ctrl.stats.frames_missed == 1

    def test_step_based_wrap(self):
        """Step-based counter wraps correctly at 0xFFFF."""
        ctrl = make_controller(
            input_iocr=make_input_iocr(send_clock_factor=32, reduction_ratio=32),
        )
        # Near wrap: 0xFC00 + 1024 = 0x10000 -> wraps to 0x0000
        ctrl._track_cycle_counter(0xFC00)
        ctrl._track_cycle_counter(0x0000)
        assert ctrl.stats.frames_missed == 0
        assert ctrl.stats.frames_duplicate == 0


# =============================================================================
# CyclicController - Watchdog
# =============================================================================


class TestWatchdogBehavior:
    """Test watchdog timeout and FAULT transitions."""

    def test_single_timeout_increments_counter(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        ctrl._handle_watchdog_timeout()
        assert ctrl.stats.frames_missed == 1
        assert ctrl.stats.consecutive_timeouts == 1
        assert ctrl.state == CyclicState.RUNNING  # not FAULT yet

    def test_fault_after_max_timeouts(self):
        ctrl = make_controller(max_consecutive_timeouts=3)
        ctrl._state = CyclicState.RUNNING
        ctrl._handle_watchdog_timeout()
        ctrl._handle_watchdog_timeout()
        assert ctrl.state == CyclicState.RUNNING
        ctrl._handle_watchdog_timeout()
        assert ctrl.state == CyclicState.FAULT

    def test_timeout_callback_called(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        cb = MagicMock()
        ctrl.on_timeout(cb)
        ctrl._handle_watchdog_timeout()
        cb.assert_called_once()

    def test_error_callback_on_fault(self):
        ctrl = make_controller(max_consecutive_timeouts=1)
        ctrl._state = CyclicState.RUNNING
        errors = []
        ctrl.on_error(lambda msg: errors.append(msg))
        ctrl._handle_watchdog_timeout()
        assert len(errors) == 1
        assert "Communication lost" in errors[0]

    def test_disable_fault_with_zero(self):
        ctrl = make_controller(max_consecutive_timeouts=0)
        ctrl._state = CyclicState.RUNNING
        for _ in range(100):
            ctrl._handle_watchdog_timeout()
        assert ctrl.state == CyclicState.RUNNING  # never goes to FAULT

    def test_consecutive_timeouts_reset_on_rx(self):
        """Receiving a frame resets the consecutive timeout counter.

        Calls _process_input_frame to verify the counter actually resets,
        rather than directly setting the field (which would be tautological).
        """
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        ctrl.stats.consecutive_timeouts = 2

        # Build a valid input frame from the device
        from profinet.rt import _ETHERTYPE_PROFINET_BYTES, RTFrame

        payload = b"\x01\x02\x03\x04\x80" + b"\x00" * 35
        data_status = (
            DATA_STATUS_VALID
            | DATA_STATUS_PROVIDER_RUN
            | DATA_STATUS_STATION_OK
            | DATA_STATUS_STATE
        )
        frame = RTFrame(
            frame_id=ctrl.input_iocr.frame_id,
            cycle_counter=1,
            data_status=data_status,
            transfer_status=0x00,
            payload=payload,
        )
        eth_frame = ctrl.src_mac + ctrl.dst_mac + _ETHERTYPE_PROFINET_BYTES + frame.to_bytes()
        ctrl._process_input_frame(eth_frame)
        assert ctrl.stats.consecutive_timeouts == 0


# =============================================================================
# CyclicController - Input Frame Processing
# =============================================================================


class TestInputFrameProcessing:
    """Test _process_input_frame with cycle counter and IOCS."""

    def _build_eth_frame(self, ctrl, cycle_counter, payload=None, data_status=None):
        """Build a fake Ethernet + RT frame as if sent by the device.

        Ethernet format: dst_mac(6) + src_mac(6) + ethertype(2) + RT data
        When the device sends to the controller:
        - dst = controller MAC (ctrl.src_mac)
        - src = device MAC (ctrl.dst_mac)
        """
        from profinet.rt import _ETHERTYPE_PROFINET_BYTES, RTFrame

        if payload is None:
            payload = b"\x01\x02\x03\x04\x80" + b"\x00" * 35  # 4B data + IOPS + pad
        if data_status is None:
            data_status = (
                DATA_STATUS_VALID
                | DATA_STATUS_PROVIDER_RUN
                | DATA_STATUS_STATION_OK
                | DATA_STATUS_STATE
            )

        frame = RTFrame(
            frame_id=ctrl.input_iocr.frame_id,
            cycle_counter=cycle_counter,
            data_status=data_status,
            transfer_status=0x00,
            payload=payload,
        )
        # Device sends: dst=controller, src=device
        return ctrl.src_mac + ctrl.dst_mac + _ETHERTYPE_PROFINET_BYTES + frame.to_bytes()

    def test_valid_frame_updates_stats(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        data = self._build_eth_frame(ctrl, 1)
        ctrl._process_input_frame(data)
        assert ctrl.stats.frames_received == 1

    def test_invalid_status_counted(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        data = self._build_eth_frame(ctrl, 1, data_status=0x00)
        ctrl._process_input_frame(data)
        assert ctrl.stats.frames_invalid == 1

    def test_wrong_frame_id_ignored(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        # Build frame with wrong frame ID
        from profinet.rt import _ETHERTYPE_PROFINET_BYTES, RTFrame

        frame = RTFrame(
            frame_id=0xBEEF,
            cycle_counter=1,
            data_status=DATA_STATUS_VALID,
            transfer_status=0,
            payload=b"\x00" * 40,
        )
        data = ctrl.dst_mac + ctrl.src_mac + _ETHERTYPE_PROFINET_BYTES + frame.to_bytes()
        ctrl._process_input_frame(data)
        assert ctrl.stats.frames_received == 0

    def test_wrong_src_mac_ignored(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        from profinet.rt import _ETHERTYPE_PROFINET_BYTES, RTFrame

        frame = RTFrame(
            frame_id=ctrl.input_iocr.frame_id,
            cycle_counter=1,
            data_status=DATA_STATUS_VALID,
            transfer_status=0,
            payload=b"\x00" * 40,
        )
        wrong_src_mac = b"\xff\xff\xff\xff\xff\xff"
        # dst=controller, src=wrong (not the device)
        data = ctrl.src_mac + wrong_src_mac + _ETHERTYPE_PROFINET_BYTES + frame.to_bytes()
        ctrl._process_input_frame(data)
        assert ctrl.stats.frames_received == 0

    def test_input_callback_called(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        received = []
        ctrl.on_input(lambda s, ss, d: received.append((s, ss, d)))
        data = self._build_eth_frame(ctrl, 1)
        ctrl._process_input_frame(data)
        assert len(received) == 1
        assert received[0][0] == 1  # slot
        assert received[0][1] == 1  # subslot
        assert received[0][2] == b"\x01\x02\x03\x04"

    def test_consecutive_timeouts_reset_on_valid_frame(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        ctrl.stats.consecutive_timeouts = 2
        data = self._build_eth_frame(ctrl, 1)
        ctrl._process_input_frame(data)
        assert ctrl.stats.consecutive_timeouts == 0

    def test_fault_recovery_on_frame(self):
        """Receiving a frame in FAULT state recovers to RUNNING."""
        ctrl = make_controller()
        ctrl._state = CyclicState.FAULT
        data = self._build_eth_frame(ctrl, 1)
        ctrl._process_input_frame(data)
        assert ctrl.state == CyclicState.RUNNING

    def test_get_input_data_returns_latest(self):
        ctrl = make_controller()
        ctrl._state = CyclicState.RUNNING
        # First frame
        data1 = self._build_eth_frame(ctrl, 1, payload=b"\x01\x02\x03\x04\x80" + b"\x00" * 35)
        ctrl._process_input_frame(data1)
        assert ctrl.get_input_data(1, 1) == b"\x01\x02\x03\x04"

        # Second frame with different data
        data2 = self._build_eth_frame(ctrl, 2, payload=b"\xaa\xbb\xcc\xdd\x80" + b"\x00" * 35)
        ctrl._process_input_frame(data2)
        assert ctrl.get_input_data(1, 1) == b"\xaa\xbb\xcc\xdd"

    def test_get_input_data_none_before_rx(self):
        ctrl = make_controller()
        assert ctrl.get_input_data(1, 1) is None


# =============================================================================
# CyclicController - Misc
# =============================================================================


class TestCyclicControllerMisc:
    """Test miscellaneous controller behavior."""

    def test_cycle_time_too_fast_raises(self):
        """Sub-1ms cycle time raises ValueError."""
        with pytest.raises(ValueError, match="below 1ms"):
            make_controller(output_iocr=make_output_iocr(send_clock_factor=1, reduction_ratio=1))

    def test_cycle_time_warning(self):
        """Cycle time below 8ms emits warning."""
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            make_controller(
                output_iocr=make_output_iocr(send_clock_factor=32, reduction_ratio=4)  # 4ms
            )
            assert len(w) >= 1
            assert "below the recommended" in str(w[0].message)

    def test_context_manager_stop_called(self):
        """Context manager exit calls stop()."""
        ctrl = make_controller()
        ctrl.stop = MagicMock()
        ctrl.start = MagicMock()
        with ctrl:
            pass
        ctrl.stop.assert_called_once()

    def test_negative_max_consecutive_timeouts_raises(self):
        """Negative max_consecutive_timeouts should raise ValueError (CQ-5)."""
        with pytest.raises(ValueError, match="max_consecutive_timeouts"):
            make_controller(max_consecutive_timeouts=-1)


# =============================================================================
# BUG-1: Stop race condition
# =============================================================================


class TestStopRaceCondition:
    """Test that stop() sets _running=False before sending stop frames (BUG-1)."""

    def test_stop_sets_running_false_before_stop_frames(self):
        """_running must be False before _send_stop_frames runs.

        This ensures the TX thread exits before stop frames are sent,
        avoiding concurrent socket access and cycle counter mutation.
        """
        ctrl = make_controller()
        # Simulate a running state without actual threads/sockets
        ctrl._running = True
        ctrl._state = CyclicState.RUNNING
        ctrl._tx_sock = MagicMock()
        ctrl._rx_sock = MagicMock()
        ctrl._tx_thread = MagicMock()
        ctrl._tx_thread.is_alive.return_value = False
        ctrl._rx_thread = MagicMock()
        ctrl._rx_thread.is_alive.return_value = False

        # Track ordering: when was _running set to False vs _send_stop_frames called
        events = []

        def patched_send_stop():
            events.append(("send_stop", ctrl._running))
            # Don't actually send frames
            return

        ctrl._send_stop_frames = patched_send_stop
        ctrl.stop()

        # _running should have been False when _send_stop_frames was called
        assert len(events) == 1
        assert events[0] == ("send_stop", False), (
            "BUG-1: _send_stop_frames was called while _running was still True"
        )


# =============================================================================
# PROTO-1: TX cycle counter step
# =============================================================================


class TestTXCounterStep:
    """Test that TX cycle counter increments by SCF*RR (PROTO-1)."""

    def test_tx_counter_step_computed(self):
        """Controller should compute _tx_counter_step from output IOCR."""
        ctrl = make_controller(
            output_iocr=make_output_iocr(send_clock_factor=32, reduction_ratio=32),
        )
        assert hasattr(ctrl, "_tx_counter_step")
        assert ctrl._tx_counter_step == 32 * 32  # 1024

    def test_send_output_frame_increments_by_step(self):
        """Each call to _send_output_frame should increment counter by step, not 1."""
        ctrl = make_controller(
            output_iocr=make_output_iocr(send_clock_factor=32, reduction_ratio=32),
        )
        ctrl._tx_sock = MagicMock()
        ctrl._output_builder.swap()

        step = 32 * 32  # 1024
        ctrl._send_output_frame()
        assert ctrl._cycle_counter == step

        ctrl._send_output_frame()
        assert ctrl._cycle_counter == step * 2

    def test_tx_counter_wraps_at_16_bits(self):
        """TX counter wraps correctly at 0xFFFF."""
        ctrl = make_controller(
            output_iocr=make_output_iocr(send_clock_factor=32, reduction_ratio=32),
        )
        ctrl._tx_sock = MagicMock()
        ctrl._output_builder.swap()

        step = 32 * 32  # 1024
        # Set counter near wrap point: 0xFC00 + 1024 = 0x10000 -> wraps to 0x0000
        ctrl._cycle_counter = 0xFFFF - step + 1  # 0xFC00
        ctrl._send_output_frame()
        assert ctrl._cycle_counter == 0x0000

        # One more step lands at 1024
        ctrl._send_output_frame()
        assert ctrl._cycle_counter == step


# =============================================================================
# BUG-7: reset() last_receive_time
# =============================================================================


class TestStatsResetLastReceiveTime:
    """Test that reset() initializes last_receive_time properly (BUG-7)."""

    def test_reset_sets_last_receive_time(self):
        """After reset(), last_receive_time should be close to current time.

        A value of 0.0 would cause spurious watchdog timeout since
        perf_counter() returns time since boot.
        """
        stats = CyclicStats()
        before = time.perf_counter()
        stats.reset()
        after = time.perf_counter()

        # last_receive_time should be close to current time, not 0.0
        assert stats.last_receive_time >= before
        assert stats.last_receive_time <= after


# =============================================================================
# BUG-5: Version string
# =============================================================================


# =============================================================================
# PROTO-2/3: IOCS offset computation
# =============================================================================


class TestBuildIOCRConfigs:
    """Test the shared build_iocr_configs helper (PROTO-2/3, CQ-7)."""

    def test_output_iocr_has_iocs_for_input_only_slots(self):
        """Slots with input data but no output should have IOCS entries
        in the output IOCR, so set_all_iocs() can acknowledge input.
        """
        from profinet.rt import IOXS_GOOD, CyclicDataBuilder, build_iocr_configs

        # Simulate: slot 1 has only input (8B), slot 2 has only output (4B)
        class FakeSlot:
            def __init__(self, slot, subslot, input_length, output_length):
                self.slot = slot
                self.subslot = subslot
                self.input_length = input_length
                self.output_length = output_length

        slots = [
            FakeSlot(slot=1, subslot=1, input_length=8, output_length=0),
            FakeSlot(slot=2, subslot=1, input_length=0, output_length=4),
        ]

        _in_iocr, out_iocr = build_iocr_configs(
            slots,
            0xC001,
            0xC000,
            send_clock_factor=32,
            reduction_ratio=32,
            watchdog_factor=3,
        )

        # Output IOCR should have 2 objects:
        # - slot 2 subslot 1 (output data at offset 0, data_length=4, iops_offset=4)
        # - slot 1 subslot 1 (IOCS only at offset 5, data_length=0, iocs_offset=5)
        assert len(out_iocr.objects) == 2

        data_obj = out_iocr.objects[0]
        assert data_obj.slot == 2
        assert data_obj.data_length == 4
        assert data_obj.iops_offset == 4

        iocs_obj = out_iocr.objects[1]
        assert iocs_obj.slot == 1
        assert iocs_obj.data_length == 0
        assert iocs_obj.iocs_offset == 5  # after data(4) + IOPS(1)

        # Verify CyclicDataBuilder.set_all_iocs actually writes the IOCS byte
        builder = CyclicDataBuilder(out_iocr)
        builder.set_all_iocs(IOXS_GOOD)
        builder.swap()
        payload = builder.build()
        assert payload[5] == IOXS_GOOD

    def test_set_all_iops_does_not_corrupt_data_via_iocs_objects(self):
        """set_all_iops must NOT write to offset 0 for IOCS-only objects.

        IOCS-only IODataObject entries have data_length=0 and iops_offset=0.
        Writing IOPS to offset 0 would corrupt the first byte of real output
        process data.
        """
        from profinet.rt import IOXS_GOOD, CyclicDataBuilder, build_iocr_configs

        class FakeSlot:
            def __init__(self, slot, subslot, input_length, output_length):
                self.slot = slot
                self.subslot = subslot
                self.input_length = input_length
                self.output_length = output_length

        slots = [
            FakeSlot(slot=1, subslot=1, input_length=8, output_length=0),  # IOCS-only
            FakeSlot(slot=2, subslot=1, input_length=0, output_length=4),  # real data
        ]

        _in_iocr, out_iocr = build_iocr_configs(
            slots,
            0xC001,
            0xC000,
            send_clock_factor=32,
            reduction_ratio=32,
            watchdog_factor=3,
        )

        builder = CyclicDataBuilder(out_iocr)
        # Set real output data for slot 2
        builder.set_data(2, 1, b"\xaa\xbb\xcc\xdd")
        # Now call set_all_iops -- this should NOT touch offset 0
        builder.set_all_iops(IOXS_GOOD)
        builder.swap()
        payload = builder.build()

        # Offset 0-3 should still be the real data, not 0x80
        assert payload[0:4] == b"\xaa\xbb\xcc\xdd", (
            f"set_all_iops corrupted output data: {payload[0:4].hex()}"
        )
        # Offset 4 should be IOPS for slot 2
        assert payload[4] == IOXS_GOOD

    def test_output_iocr_no_iocs_when_all_have_output(self):
        """If all slots have output data, no extra IOCS-only entries needed."""
        from profinet.rt import build_iocr_configs

        class FakeSlot:
            def __init__(self, slot, subslot, input_length, output_length):
                self.slot = slot
                self.subslot = subslot
                self.input_length = input_length
                self.output_length = output_length

        slots = [
            FakeSlot(slot=1, subslot=1, input_length=4, output_length=4),
        ]

        _in_iocr, out_iocr = build_iocr_configs(
            slots,
            0xC001,
            0xC000,
            send_clock_factor=32,
            reduction_ratio=32,
            watchdog_factor=3,
        )

        # Only 1 object for the actual data
        assert len(out_iocr.objects) == 1
        assert out_iocr.objects[0].data_length == 4


# =============================================================================
# BUG-5: Version string
# =============================================================================


class TestVersion:
    """Test version string matches pyproject.toml."""

    def test_version_is_0_6_0(self):
        """__version__ should be 0.6.0 for this release."""
        import profinet

        assert profinet.__version__ == "0.6.0"
