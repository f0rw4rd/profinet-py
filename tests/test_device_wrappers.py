"""Tests for ProfinetDevice wrapper methods (read/write, I&M, diagnosis,
connection lifecycle, alarm listener guards).

The RPC layer is mocked; these tests pin delegation, argument mapping,
data building (I&M writes), validation, and connection state handling.
"""

import struct
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from profinet import indices
from profinet.device import ProfinetDevice, WriteItem
from profinet.exceptions import RPCError

CTRL_MAC = b"\x00\x11\x22\x33\x44\x55"


def make_info(mac="02:00:00:00:00:01"):
    return SimpleNamespace(
        name="dev",
        ip="192.168.0.10",
        mac=mac,
        vendor_id=1,
        device_id=1,
        device_type="test",
        netmask="255.255.255.0",
        gateway="0.0.0.0",
        device_roles=0,
        vendor_name="Test",
    )


def make_connected_device(**info_kwargs):
    device = ProfinetDevice(make_info(**info_kwargs), "eth0", CTRL_MAC, timeout=1.0)
    device._rpc = MagicMock()
    device._connected = True
    return device


class TestProperties:
    def test_name_ip(self):
        device = make_connected_device()
        assert device.name == "dev"
        assert device.ip == "192.168.0.10"

    def test_mac_from_string(self):
        assert make_connected_device().mac == "02:00:00:00:00:01"

    def test_mac_from_bytes(self):
        device = make_connected_device(mac=b"\x02\x00\x00\x00\x00\x01")
        assert device.mac == "02:00:00:00:00:01"


class TestReadWrite:
    def test_read_returns_payload(self):
        device = make_connected_device()
        device._rpc.read.return_value = SimpleNamespace(payload=b"\x01\x02")
        assert device.read(1, 2, 0xAFF0) == b"\x01\x02"
        device._rpc.read.assert_called_once_with(api=0, slot=1, subslot=2, idx=0xAFF0)

    def test_write_delegates(self):
        device = make_connected_device()
        device.write(1, 2, 0xAFF1, b"\xab", api=3)
        device._rpc.write.assert_called_once_with(
            api=3, slot=1, subslot=2, idx=0xAFF1, data=b"\xab"
        )

    def test_write_multiple_maps_items(self):
        device = make_connected_device()
        device.write_multiple([WriteItem(slot=1, subslot=2, index=0xAFF1, data=b"\x01")])
        device._rpc.write_multiple.assert_called_once_with([(1, 2, 0xAFF1, b"\x01", 0)])


class TestImWrappers:
    @pytest.mark.parametrize("n", [0, 1, 2, 3, 4, 5])
    def test_read_im_delegates(self, n):
        device = make_connected_device()
        result = getattr(device, f"read_im{n}")(slot=1, subslot=2)
        rpc_method = getattr(device._rpc, f"read_im{n}")
        rpc_method.assert_called_once_with(1, 2)
        assert result is rpc_method.return_value

    def test_read_all_im(self):
        device = make_connected_device()
        assert device.read_all_im() is device._rpc.read_all_im.return_value

    def test_write_im1_builds_padded_block(self):
        device = make_connected_device()
        device.write_im1("func", "loc")
        kwargs = device._rpc.write.call_args.kwargs
        assert kwargs["idx"] == indices.IM1
        payload = kwargs["data"]
        assert len(payload) == 62  # header 6 + padding 2 + 32 + 22
        assert struct.unpack(">HH", payload[0:4]) == (0x0021, 58)
        assert payload[8:40] == b"func".ljust(32, b" ")
        assert payload[40:62] == b"loc".ljust(22, b" ")

    def test_write_im1_validates_lengths(self):
        device = make_connected_device()
        with pytest.raises(ValueError, match="tag_function"):
            device.write_im1("x" * 33, "loc")
        with pytest.raises(ValueError, match="tag_location"):
            device.write_im1("func", "x" * 23)

    def test_write_im2_builds_block_and_validates(self):
        device = make_connected_device()
        device.write_im2("2026-07-21 18:00")
        payload = device._rpc.write.call_args.kwargs["data"]
        assert struct.unpack(">HH", payload[0:4]) == (0x0022, 20)
        assert payload[8:24] == b"2026-07-21 18:00"
        with pytest.raises(ValueError, match="date"):
            device.write_im2("x" * 17)

    def test_write_im3_builds_block_and_validates(self):
        device = make_connected_device()
        device.write_im3("descriptor")
        payload = device._rpc.write.call_args.kwargs["data"]
        assert struct.unpack(">HH", payload[0:4]) == (0x0023, 58)
        assert payload[8:62] == b"descriptor".ljust(54, b" ")
        with pytest.raises(ValueError, match="descriptor"):
            device.write_im3("x" * 55)


class TestDiagnosisWrappers:
    def test_delegation(self):
        device = make_connected_device()
        assert device.read_module_diff() is device._rpc.read_module_diff.return_value
        assert device.read_diagnosis(1, 2, 0xF00C) is device._rpc.read_diagnosis.return_value
        device._rpc.read_diagnosis.assert_called_once_with(1, 2, 0xF00C)
        assert device.read_all_diagnosis() is device._rpc.read_all_diagnosis.return_value
        assert device.discover_slots() is device._rpc.discover_slots.return_value
        assert device.read_topology() is device._rpc.read_pd_real_data.return_value


class TestReadAlarm:
    def test_returns_none_on_rpc_error(self):
        device = make_connected_device()
        device._rpc.read.side_effect = RPCError("nope")
        assert device.read_alarm() is None

    def test_returns_none_on_short_payload(self):
        device = make_connected_device()
        device._rpc.read.return_value = SimpleNamespace(payload=b"\x00" * 4)
        assert device.read_alarm() is None

    def test_parses_alarm_payload(self):
        body = struct.pack(">HIHHIIH", 0x0001, 0, 1, 1, 0x01, 0x01, 0x0400 | 5)
        block = struct.pack(">HHBB", 0x0002, len(body) + 2, 1, 0) + body + b"\x00\x00"
        device = make_connected_device()
        device._rpc.read.return_value = SimpleNamespace(payload=block)
        alarm = device.read_alarm()
        assert alarm is not None
        assert alarm.slot_number == 1


class TestConnectionLifecycle:
    def test_connect_success(self):
        device = ProfinetDevice(make_info(), "eth0", CTRL_MAC)
        rpc = MagicMock()
        with patch("profinet.device.RPCCon", return_value=rpc):
            device.connect()
        rpc.connect.assert_called_once_with(CTRL_MAC)
        assert device._connected is True

    def test_connect_failure_wrapped(self):
        from profinet.exceptions import RPCConnectionError

        device = ProfinetDevice(make_info(), "eth0", CTRL_MAC)
        rpc = MagicMock()
        rpc.connect.side_effect = RPCError("refused")
        with patch("profinet.device.RPCCon", return_value=rpc):
            with pytest.raises(RPCConnectionError):
                device.connect()
        rpc.close.assert_called_once()
        assert device._rpc is None

    def test_connect_noop_when_connected(self):
        device = make_connected_device()
        rpc = device._rpc
        device.connect()
        assert device._rpc is rpc

    def test_disconnect_and_close(self):
        device = make_connected_device()
        rpc = device._rpc
        device.disconnect()
        rpc.disconnect.assert_called_once()
        assert device._connected is False
        device.close()
        rpc.close.assert_called_once()
        assert device._rpc is None

    def test_close_stops_alarm_listener(self):
        device = make_connected_device()
        listener = MagicMock()
        device._alarm_listener = listener
        device.close()
        listener.stop.assert_called_once()
        assert device._alarm_listener is None

    def test_context_manager(self):
        device = ProfinetDevice(make_info(), "eth0", CTRL_MAC)
        rpc = MagicMock()
        with patch("profinet.device.RPCCon", return_value=rpc):
            with device as d:
                assert d is device
                assert device._connected is True
        assert device._rpc is None

    def test_release_ar_clears_state_only_for_current_rpc(self):
        device = make_connected_device()
        current = device._rpc
        other = MagicMock()
        device._release_ar(other)
        other.disconnect.assert_called_once()
        other.close.assert_called_once()
        assert device._rpc is current  # untouched, other was not the active AR
        device._release_ar(current)
        assert device._rpc is None
        assert device._connected is False

    def test_release_ar_swallows_disconnect_errors(self):
        device = make_connected_device()
        device._rpc.disconnect.side_effect = OSError("gone")
        device._release_ar(device._rpc)
        assert device._rpc is None


class TestAlarmListenerGuards:
    def test_requires_connection(self):
        device = ProfinetDevice(make_info(), "eth0", CTRL_MAC)
        with pytest.raises(RuntimeError, match="connected"):
            device.start_alarm_listener()

    def test_requires_alarm_cr(self):
        device = make_connected_device()
        device._rpc._alarm_cr_enabled = False
        with pytest.raises(RuntimeError, match="AlarmCR"):
            device.start_alarm_listener()

    def test_start_and_running_property(self):
        device = make_connected_device()
        device._rpc._alarm_cr_enabled = True
        device._rpc._alarm_ref = 1
        device._rpc._device_alarm_ref = 42
        with patch("profinet.device.AlarmListener") as listener_cls:
            listener_cls.return_value.is_running = True
            device.on_alarm(lambda a: None)
            device.start_alarm_listener()
            assert device.alarm_listener_running is True
            listener_cls.return_value.start.assert_called_once()
            listener_cls.return_value.add_callback.assert_called_once()
        device.stop_alarm_listener()
        assert device._alarm_listener is None

    def test_on_alarm_forwards_to_running_listener(self):
        device = make_connected_device()
        listener = MagicMock()
        device._alarm_listener = listener
        callback = lambda a: None  # noqa: E731
        device.on_alarm(callback)
        listener.add_callback.assert_called_once_with(callback)


class TestGetInfo:
    def test_collects_im0_and_survives_failures(self):
        device = make_connected_device()
        device._rpc.read_im0.return_value = "im0-data"
        with patch("profinet.device.epm_lookup", side_effect=OSError("no epm")):
            info = device.get_info()
        assert info.im0 == "im0-data"
        assert info.name == "dev"

    def test_im0_failure_tolerated(self):
        device = make_connected_device()
        device._rpc.read_im0.side_effect = RPCError("unsupported")
        with patch("profinet.device.epm_lookup", return_value=[]):
            info = device.get_info()
        assert info.im0 is None

    def test_topology_included_on_request(self):
        device = make_connected_device()
        device._rpc.read_im0.return_value = None
        device._rpc.read_pd_real_data.return_value = "topo"
        with patch("profinet.device.epm_lookup", return_value=[]):
            info = device.get_info(include_topology=True)
        assert info.topology == "topo"
