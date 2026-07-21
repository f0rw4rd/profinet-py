"""Tests for ProfinetDevice.start_cyclic lifecycle (PR #16 flow).

Covers the flag-controlled ordering (RT before/after PrmEnd, optional
ApplicationReady), AR re-open behavior, alarm-listener handling, and
rollback on mid-startup failure. All RPC/RT machinery is mocked; the
call *order* across mocks is recorded to pin the lifecycle sequence.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from profinet.device import ProfinetDevice

CTRL_MAC = b"\x00\x11\x22\x33\x44\x55"


def make_device():
    info = SimpleNamespace(
        name="dev",
        ip="192.168.0.10",
        mac="d0:c8:57:e0:1c:2c",
        vendor_id=1,
        device_id=1,
        device_type="test",
        netmask="255.255.255.0",
        gateway="0.0.0.0",
        device_roles=0,
        vendor_name="Test",
    )
    return ProfinetDevice(info, "eth0", CTRL_MAC, timeout=1.0)


class Harness:
    """Patches RPCCon, CyclicController, and build_iocr_configs, recording
    the order of lifecycle calls in self.calls."""

    def __init__(self, connect_result=None):
        self.calls = []
        self.rpc = MagicMock()
        self.cyclic = MagicMock()
        self.connect_result = connect_result or SimpleNamespace(
            has_cyclic=True, input_frame_id=0xC001, output_frame_id=0x8002
        )

        self.rpc.connect.side_effect = self._log("connect", self.connect_result)
        self.rpc.prm_end.side_effect = self._log("prm_end")
        self.rpc.application_ready.side_effect = self._log("application_ready")
        self.rpc.disconnect.side_effect = self._log("disconnect")
        self.rpc.close.side_effect = self._log("close")
        self.cyclic.start.side_effect = self._log("cyclic.start")
        self.cyclic.stop.side_effect = self._log("cyclic.stop")

    def _log(self, name, result=None):
        def side_effect(*args, **kwargs):
            self.calls.append(name)
            return result

        return side_effect

    def patches(self):
        return (
            patch("profinet.device.RPCCon", return_value=self.rpc),
            patch("profinet.cyclic.CyclicController", return_value=self.cyclic),
            patch(
                "profinet.rt.build_iocr_configs",
                return_value=(MagicMock(), MagicMock()),
            ),
        )

    def start_cyclic(self, device, **kwargs):
        kwargs.setdefault("start_alarm_listener", False)
        p1, p2, p3 = self.patches()
        with p1, p2, p3:
            return device.start_cyclic(
                SimpleNamespace(
                    slots=[], send_clock_factor=32, reduction_ratio=32, watchdog_factor=3
                ),
                **kwargs,
            )


class TestStartCyclicOrdering:
    def test_default_starts_rt_before_prm_end(self):
        h = Harness()
        result = h.start_cyclic(make_device())
        assert result is h.cyclic
        assert h.calls.index("cyclic.start") < h.calls.index("prm_end")
        assert h.calls.index("prm_end") < h.calls.index("application_ready")

    def test_rt_after_application_ready_when_disabled(self):
        h = Harness()
        h.start_cyclic(make_device(), start_rt_before_prm_end=False)
        assert h.calls.index("cyclic.start") > h.calls.index("application_ready")
        assert h.calls.count("cyclic.start") == 1

    def test_application_ready_skippable(self):
        h = Harness()
        h.start_cyclic(make_device(), confirm_application_ready=False)
        assert "application_ready" not in h.calls
        assert "prm_end" in h.calls

    def test_device_state_committed(self):
        h = Harness()
        device = make_device()
        h.start_cyclic(device)
        assert device._rpc is h.rpc
        assert device._connected is True


class TestStartCyclicArHandling:
    def test_existing_ar_released_before_new_connect(self):
        h = Harness()
        device = make_device()
        old_rpc = MagicMock()
        old_rpc.disconnect.side_effect = h._log("old.disconnect")
        old_rpc.close.side_effect = h._log("old.close")
        device._rpc = old_rpc
        device._connected = True

        h.start_cyclic(device)

        assert h.calls.index("old.disconnect") < h.calls.index("connect")
        assert h.calls.index("old.close") < h.calls.index("connect")
        assert device._rpc is h.rpc

    def test_running_alarm_listener_stopped_with_old_ar(self):
        """A listener bound to the released AR must not survive it."""
        h = Harness()
        device = make_device()
        old_listener = MagicMock()
        old_listener.stop.side_effect = h._log("old_listener.stop")
        device._alarm_listener = old_listener
        device._rpc = MagicMock()
        device._connected = True

        h.start_cyclic(device)

        assert h.calls.index("old_listener.stop") < h.calls.index("connect")
        assert device._alarm_listener is None


class TestStartCyclicRollback:
    def test_prm_end_failure_rolls_back(self):
        h = Harness()
        h.rpc.prm_end.side_effect = RuntimeError("boom")
        device = make_device()

        with pytest.raises(RuntimeError, match="boom"):
            h.start_cyclic(device)

        assert "cyclic.stop" in h.calls  # RT was already started
        assert "close" in h.calls
        assert device._rpc is None
        assert device._connected is False

    def test_no_cyclic_result_raises_and_rolls_back(self):
        h = Harness(connect_result=SimpleNamespace(has_cyclic=False))
        device = make_device()

        with pytest.raises(RuntimeError, match="Cyclic IO not established"):
            h.start_cyclic(device)

        assert "cyclic.start" not in h.calls
        assert "close" in h.calls
        assert device._rpc is None

    def test_application_ready_failure_stops_started_rt(self):
        h = Harness()
        h.rpc.application_ready.side_effect = RuntimeError("timeout")
        device = make_device()

        with pytest.raises(RuntimeError, match="timeout"):
            h.start_cyclic(device)

        assert h.calls.index("cyclic.stop") > h.calls.index("cyclic.start")
        assert device._connected is False

    def test_release_failure_during_rollback_does_not_mask_error(self):
        h = Harness()
        h.rpc.prm_end.side_effect = RuntimeError("original")
        h.rpc.disconnect.side_effect = OSError("release failed")
        device = make_device()

        with pytest.raises(RuntimeError, match="original"):
            h.start_cyclic(device)

        assert device._rpc is None
