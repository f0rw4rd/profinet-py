"""Tests for profinet.alarm_listener module."""

from profinet.alarm_listener import (
    FRAME_ID_ALARM_HIGH,
    FRAME_ID_ALARM_LOW,
    AlarmEndpoint,
    AlarmListener,
)


class TestAlarmEndpoint:
    """Test AlarmEndpoint configuration dataclass."""

    def test_default_transport(self):
        """Test default transport is Layer 2."""
        endpoint = AlarmEndpoint(
            interface="eth0",
            controller_ref=1,
            device_ref=42,
            device_mac=b"\xd0\xc8\x57\xe0\x1c\x2c",
        )
        assert endpoint.transport == 0

    def test_all_fields(self):
        """Test all fields can be set."""
        endpoint = AlarmEndpoint(
            interface="eth0",
            controller_ref=100,
            device_ref=200,
            device_mac=b"\x00\x11\x22\x33\x44\x55",
            transport=1,  # UDP
        )
        assert endpoint.interface == "eth0"
        assert endpoint.controller_ref == 100
        assert endpoint.device_ref == 200
        assert endpoint.device_mac == b"\x00\x11\x22\x33\x44\x55"
        assert endpoint.transport == 1


class TestAlarmListener:
    """Test AlarmListener class."""

    def test_init(self):
        """Test initialization."""
        endpoint = AlarmEndpoint(
            interface="lo",
            controller_ref=1,
            device_ref=42,
            device_mac=b"\x00" * 6,
        )
        listener = AlarmListener(endpoint)

        assert listener.endpoint == endpoint
        assert not listener.is_running
        assert len(listener._callbacks) == 0

    def test_add_callback(self):
        """Test adding callback."""
        endpoint = AlarmEndpoint(
            interface="lo",
            controller_ref=1,
            device_ref=42,
            device_mac=b"\x00" * 6,
        )
        listener = AlarmListener(endpoint)

        def my_callback(alarm):
            pass

        listener.add_callback(my_callback)
        assert my_callback in listener._callbacks

    def test_remove_callback(self):
        """Test removing callback."""
        endpoint = AlarmEndpoint(
            interface="lo",
            controller_ref=1,
            device_ref=42,
            device_mac=b"\x00" * 6,
        )
        listener = AlarmListener(endpoint)

        def my_callback(alarm):
            pass

        listener.add_callback(my_callback)
        listener.remove_callback(my_callback)
        assert my_callback not in listener._callbacks

    def test_remove_nonexistent_callback(self):
        """Test removing non-existent callback doesn't raise."""
        endpoint = AlarmEndpoint(
            interface="lo",
            controller_ref=1,
            device_ref=42,
            device_mac=b"\x00" * 6,
        )
        listener = AlarmListener(endpoint)

        def my_callback(alarm):
            pass

        # Should not raise
        listener.remove_callback(my_callback)

    def test_is_running_property(self):
        """Test is_running property reflects state."""
        endpoint = AlarmEndpoint(
            interface="lo",
            controller_ref=1,
            device_ref=42,
            device_mac=b"\x00" * 6,
        )
        listener = AlarmListener(endpoint)

        assert not listener.is_running
        listener._running = True
        assert listener.is_running

    def test_controller_mac_default(self):
        """Test default controller MAC is zeros."""
        endpoint = AlarmEndpoint(
            interface="lo",
            controller_ref=1,
            device_ref=42,
            device_mac=b"\x00" * 6,
        )
        listener = AlarmListener(endpoint)
        assert listener.controller_mac == b"\x00" * 6

    def test_controller_mac_custom(self):
        """Test custom controller MAC."""
        endpoint = AlarmEndpoint(
            interface="lo",
            controller_ref=1,
            device_ref=42,
            device_mac=b"\x00" * 6,
        )
        custom_mac = b"\x11\x22\x33\x44\x55\x66"
        listener = AlarmListener(endpoint, controller_mac=custom_mac)
        assert listener.controller_mac == custom_mac


class TestFrameIDConstants:
    """Test frame ID constants."""

    def test_alarm_high_frame_id(self):
        """Test high priority alarm frame ID."""
        assert FRAME_ID_ALARM_HIGH == 0xFC01

    def test_alarm_low_frame_id(self):
        """Test low priority alarm frame ID."""
        assert FRAME_ID_ALARM_LOW == 0xFE01
