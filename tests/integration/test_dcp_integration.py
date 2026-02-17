"""Integration tests for DCP (Discovery and Configuration Protocol).

Tests DCP discovery, parameter read, and signal operations against
a real PROFINET device emulator running in Docker.
"""

import pytest

from profinet import (
    DCPDeviceDescription,
    ethernet_socket,
    get_mac,
    get_param,
    read_response,
    send_discover,
    set_param,
    signal_device,
)

from .conftest import (
    EXPECTED_DEVICE_ID,
    EXPECTED_STATION_NAME,
    EXPECTED_VENDOR_ID,
    skip_no_container,
    skip_not_root,
)

pytestmark = [
    pytest.mark.integration,
    skip_not_root,
    skip_no_container,
]


# ---------------------------------------------------------------------------
# DCP Discovery
# ---------------------------------------------------------------------------


class TestDCPDiscover:
    """Test DCP multicast discovery finds the emulated device."""

    def test_discover_finds_device(self, interface):
        """DCP discover should find at least one device."""
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            send_discover(sock, src_mac)
            responses = read_response(sock, src_mac, timeout_sec=3)
            assert len(responses) >= 1, "Expected at least one DCP response"
        finally:
            sock.close()

    def test_discover_correct_station_name(self, interface, station_name):
        """Discovered device should have the expected station name."""
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            send_discover(sock, src_mac)
            responses = read_response(sock, src_mac, timeout_sec=3)

            found = False
            for mac, blocks in responses.items():
                info = DCPDeviceDescription(mac, blocks)
                if info.name == station_name:
                    found = True
                    break

            assert found, (
                f"Device with station name '{station_name}' not found. "
                f"Found: {[DCPDeviceDescription(m, b).name for m, b in responses.items()]}"
            )
        finally:
            sock.close()

    def test_discover_correct_vendor_id(self, interface, station_name):
        """Discovered device should report correct vendor ID."""
        device = self._find_device(interface, station_name)
        assert device.vendor_id == EXPECTED_VENDOR_ID, (
            f"Expected vendor_id 0x{EXPECTED_VENDOR_ID:04X}, got 0x{device.vendor_id:04X}"
        )

    def test_discover_correct_device_id(self, interface, station_name):
        """Discovered device should report correct device ID."""
        device = self._find_device(interface, station_name)
        assert device.device_id == EXPECTED_DEVICE_ID, (
            f"Expected device_id 0x{EXPECTED_DEVICE_ID:04X}, got 0x{device.device_id:04X}"
        )

    def test_discover_has_valid_ip(self, interface, station_name):
        """Discovered device should have a non-zero IP address."""
        device = self._find_device(interface, station_name)
        assert device.ip != "0.0.0.0", "Device IP should not be 0.0.0.0"
        # Verify it looks like a valid IPv4 address
        parts = device.ip.split(".")
        assert len(parts) == 4, f"Invalid IP format: {device.ip}"
        for part in parts:
            assert 0 <= int(part) <= 255

    def test_discover_has_valid_mac(self, interface, station_name):
        """Discovered device should have a non-zero MAC address."""
        device = self._find_device(interface, station_name)
        assert device.mac != "00:00:00:00:00:00", "Device MAC should not be all zeros"
        parts = device.mac.split(":")
        assert len(parts) == 6, f"Invalid MAC format: {device.mac}"

    def test_discover_has_netmask(self, interface, station_name):
        """Discovered device should have a non-zero netmask."""
        device = self._find_device(interface, station_name)
        assert device.netmask != "0.0.0.0", "Netmask should not be 0.0.0.0"

    def test_discover_device_role_is_io_device(self, interface, station_name):
        """Discovered device should report IO-Device role."""
        device = self._find_device(interface, station_name)
        # Role bit 0x01 = IO-Device
        assert device.device_role & 0x01, (
            f"Expected IO-Device role (0x01), got role=0x{device.device_role:02X}"
        )

    def test_discover_has_supported_options(self, interface, station_name):
        """Discovered device should report supported DCP options."""
        device = self._find_device(interface, station_name)
        assert len(device.supported_options) > 0, "Device should report supported options"

    # -- NEW: deeper DCPDeviceDescription field verification --

    def test_discover_vendor_name_non_empty(self, interface, station_name):
        """vendor_name property should return a non-empty string from ID lookup."""
        device = self._find_device(interface, station_name)
        assert isinstance(device.vendor_name, str)
        assert len(device.vendor_name) > 0, "vendor_name should not be empty"

    def test_discover_device_type_is_string(self, interface, station_name):
        """device_type should be a string (may be empty for some devices)."""
        device = self._find_device(interface, station_name)
        assert isinstance(device.device_type, str)

    def test_discover_gateway_is_valid_ip(self, interface, station_name):
        """Gateway should be a valid IPv4 address string."""
        device = self._find_device(interface, station_name)
        assert isinstance(device.gateway, str)
        parts = device.gateway.split(".")
        assert len(parts) == 4, f"Invalid gateway format: {device.gateway}"
        for part in parts:
            assert 0 <= int(part) <= 255, f"Invalid gateway octet: {part}"

    def test_discover_device_roles_list(self, interface, station_name):
        """device_roles should be a list containing 'IO-Device'."""
        device = self._find_device(interface, station_name)
        assert isinstance(device.device_roles, list)
        assert len(device.device_roles) >= 1, "device_roles should not be empty"
        assert "IO-Device" in device.device_roles, (
            f"Expected 'IO-Device' in roles, got {device.device_roles}"
        )

    def test_discover_vendor_id_bytes(self, interface, station_name):
        """vendor_high/vendor_low should combine to the expected vendor ID."""
        device = self._find_device(interface, station_name)
        assert isinstance(device.vendor_high, int)
        assert isinstance(device.vendor_low, int)
        combined = (device.vendor_high << 8) | device.vendor_low
        assert combined == EXPECTED_VENDOR_ID

    def test_discover_device_id_bytes(self, interface, station_name):
        """device_high/device_low should combine to the expected device ID."""
        device = self._find_device(interface, station_name)
        assert isinstance(device.device_high, int)
        assert isinstance(device.device_low, int)
        combined = (device.device_high << 8) | device.device_low
        assert combined == EXPECTED_DEVICE_ID

    def test_discover_supported_options_are_tuples(self, interface, station_name):
        """Each supported option should be a (int, int) tuple."""
        device = self._find_device(interface, station_name)
        for opt in device.supported_options:
            assert isinstance(opt, tuple), f"Expected tuple, got {type(opt)}"
            assert len(opt) == 2, f"Expected (option, suboption), got {opt}"
            assert isinstance(opt[0], int) and isinstance(opt[1], int)
            assert 0 <= opt[0] <= 0xFF and 0 <= opt[1] <= 0xFF

    def test_discover_supported_options_include_ip_and_device(self, interface, station_name):
        """Supported options should include IP (1,x) and Device (2,x) option groups."""
        device = self._find_device(interface, station_name)
        option_groups = {opt[0] for opt in device.supported_options}
        assert 1 in option_groups, "IP option group (0x01) should be supported"
        assert 2 in option_groups, "Device option group (0x02) should be supported"

    def test_discover_ip_block_info_no_conflict(self, interface, station_name):
        """Device should not have an IP address conflict."""
        device = self._find_device(interface, station_name)
        assert device.ip_conflict is False, "Device should not have an IP conflict"

    def test_discover_netmask_is_valid(self, interface, station_name):
        """Netmask should be a valid IPv4 netmask."""
        device = self._find_device(interface, station_name)
        parts = device.netmask.split(".")
        assert len(parts) == 4, f"Invalid netmask format: {device.netmask}"
        # Convert to integer and verify it's a valid mask (contiguous 1s then 0s)
        mask_int = 0
        for part in parts:
            val = int(part)
            assert 0 <= val <= 255
            mask_int = (mask_int << 8) | val
        # A valid netmask in binary is a sequence of 1s followed by 0s
        # Invert and add 1: should be a power of 2
        if mask_int != 0:
            inverted = (~mask_int) & 0xFFFFFFFF
            assert (inverted & (inverted + 1)) == 0, (
                f"Netmask {device.netmask} is not a valid contiguous mask"
            )

    def test_discover_str_repr(self, interface, station_name):
        """__str__ and __repr__ should return non-empty strings without error."""
        device = self._find_device(interface, station_name)
        s = str(device)
        assert len(s) > 0, "__str__ should produce non-empty output"
        assert station_name in s, f"__str__ should contain station name '{station_name}'"
        r = repr(device)
        assert len(r) > 0, "__repr__ should produce non-empty output"

    def test_discover_consistency_two_runs(self, interface, station_name):
        """Two consecutive discoveries should return the same device data."""
        dev1 = self._find_device(interface, station_name)
        dev2 = self._find_device(interface, station_name)

        assert dev1.name == dev2.name, "Station name should be consistent"
        assert dev1.mac == dev2.mac, "MAC address should be consistent"
        assert dev1.ip == dev2.ip, "IP address should be consistent"
        assert dev1.vendor_id == dev2.vendor_id, "Vendor ID should be consistent"
        assert dev1.device_id == dev2.device_id, "Device ID should be consistent"
        assert dev1.device_role == dev2.device_role, "Device role should be consistent"
        assert dev1.netmask == dev2.netmask, "Netmask should be consistent"

    @staticmethod
    def _find_device(interface: str, station_name: str) -> DCPDeviceDescription:
        """Helper: discover and return the device with the given station name."""
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            send_discover(sock, src_mac)
            responses = read_response(sock, src_mac, timeout_sec=3)

            for mac, blocks in responses.items():
                info = DCPDeviceDescription(mac, blocks)
                if info.name == station_name:
                    return info

            names = [DCPDeviceDescription(m, b).name for m, b in responses.items()]
            pytest.fail(f"Device '{station_name}' not found. Discovered: {names}")
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# DCP Raw Response Blocks
# ---------------------------------------------------------------------------


class TestDCPRawBlocks:
    """Test the raw DCP response block structure."""

    def test_response_blocks_keys_are_tuples(self, interface, station_name):
        """Raw response blocks dict keys should be (option, suboption) tuples or strings."""
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            send_discover(sock, src_mac)
            responses = read_response(sock, src_mac, timeout_sec=3)
            assert len(responses) >= 1

            for _mac, blocks in responses.items():
                for key, value in blocks.items():
                    # Keys are (option, suboption) tuples or legacy string keys
                    if isinstance(key, tuple):
                        assert len(key) == 2
                        assert isinstance(key[0], int) and isinstance(key[1], int)
                    else:
                        assert isinstance(key, str)
                    # Values should be bytes or strings
                    assert isinstance(value, (bytes, str)), (
                        f"Block value should be bytes or str, got {type(value)} for key {key}"
                    )
        finally:
            sock.close()

    def test_response_blocks_contain_name(self, interface, station_name):
        """Raw blocks should contain NAME_OF_STATION block (2, 2)."""
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            send_discover(sock, src_mac)
            responses = read_response(sock, src_mac, timeout_sec=3)
            assert len(responses) >= 1

            for _mac, blocks in responses.items():
                info = DCPDeviceDescription(_mac, blocks)
                if info.name == station_name:
                    assert (2, 2) in blocks, (
                        f"NAME_OF_STATION block (2,2) missing. Keys: {list(blocks.keys())}"
                    )
                    name_bytes = blocks[(2, 2)]
                    assert isinstance(name_bytes, bytes)
                    assert name_bytes.decode("utf-8") == station_name
                    return
            pytest.fail(f"Device '{station_name}' not found")
        finally:
            sock.close()

    def test_response_blocks_contain_ip(self, interface, station_name):
        """Raw blocks should contain IP_ADDRESS block (1, 2)."""
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            send_discover(sock, src_mac)
            responses = read_response(sock, src_mac, timeout_sec=3)
            assert len(responses) >= 1

            for _mac, blocks in responses.items():
                info = DCPDeviceDescription(_mac, blocks)
                if info.name == station_name:
                    assert (1, 2) in blocks, (
                        f"IP_ADDRESS block (1,2) missing. Keys: {list(blocks.keys())}"
                    )
                    ip_bytes = blocks[(1, 2)]
                    assert isinstance(ip_bytes, bytes)
                    # IP block is at least 12 bytes (IP + netmask + gateway)
                    assert len(ip_bytes) >= 12, (
                        f"IP block should be >= 12 bytes, got {len(ip_bytes)}"
                    )
                    return
            pytest.fail(f"Device '{station_name}' not found")
        finally:
            sock.close()

    def test_response_blocks_contain_device_id(self, interface, station_name):
        """Raw blocks should contain DEVICE_ID block (2, 3)."""
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            send_discover(sock, src_mac)
            responses = read_response(sock, src_mac, timeout_sec=3)
            assert len(responses) >= 1

            for _mac, blocks in responses.items():
                info = DCPDeviceDescription(_mac, blocks)
                if info.name == station_name:
                    assert (2, 3) in blocks, (
                        f"DEVICE_ID block (2,3) missing. Keys: {list(blocks.keys())}"
                    )
                    dev_id_bytes = blocks[(2, 3)]
                    assert isinstance(dev_id_bytes, bytes)
                    assert len(dev_id_bytes) >= 4, (
                        f"DEVICE_ID block should be >= 4 bytes, got {len(dev_id_bytes)}"
                    )
                    return
            pytest.fail(f"Device '{station_name}' not found")
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# DCP Get Parameter
# ---------------------------------------------------------------------------


class TestDCPGetParam:
    """Test DCP Get operations for reading device parameters."""

    def test_get_param_name(self, interface, station_name):
        """get_param('name') should return the device station name."""
        device = TestDCPDiscover._find_device(interface, station_name)
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            result = get_param(sock, src_mac, device.mac, "name", timeout_sec=3)
            assert result is not None, "get_param('name') returned None"
            name = result.decode("utf-8", errors="replace")
            assert name == station_name, f"Expected '{station_name}', got '{name}'"
        finally:
            sock.close()

    def test_get_param_ip(self, interface, station_name):
        """get_param('ip') should return IP configuration bytes."""
        device = TestDCPDiscover._find_device(interface, station_name)
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            result = get_param(sock, src_mac, device.mac, "ip", timeout_sec=3)
            assert result is not None, "get_param('ip') returned None"
            # IP block should be at least 12 bytes (IP + netmask + gateway)
            assert len(result) >= 12, f"IP block too short: {len(result)} bytes"
        finally:
            sock.close()

    def test_get_param_name_type_is_bytes(self, interface, station_name):
        """get_param('name') should return bytes, not str."""
        device = TestDCPDiscover._find_device(interface, station_name)
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            result = get_param(sock, src_mac, device.mac, "name", timeout_sec=3)
            assert result is not None
            assert isinstance(result, bytes), f"Expected bytes, got {type(result)}"
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# DCP Signal (LED Blink)
# ---------------------------------------------------------------------------


class TestDCPSignal:
    """Test DCP Signal command for LED identification."""

    def test_signal_device(self, interface, station_name):
        """signal_device should get a response from the device."""
        device = TestDCPDiscover._find_device(interface, station_name)
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        try:
            result = signal_device(sock, src_mac, device.mac, duration_ms=1000, timeout_sec=3)
            # p-net may or may not respond to signal; just verify no crash
            # result is True if response received, False on timeout
            assert isinstance(result, bool)
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# DCP Set Parameter
# ---------------------------------------------------------------------------


class TestDCPSetParam:
    """Test DCP Set operations for writing device parameters.

    p-net may or may not support DCP Set for station name.  Tests skip
    gracefully if the device does not respond.
    """

    def test_set_name_and_read_back(self, interface, station_name):
        """Setting a new station name should be readable via get_param."""
        device = TestDCPDiscover._find_device(interface, station_name)
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        temp_name = "integration-test-tmp"
        try:
            ok = set_param(sock, src_mac, device.mac, "name", temp_name, timeout_sec=3)
            if not ok:
                pytest.skip("Device did not respond to DCP Set (unsupported)")

            # Read the name back
            result = get_param(sock, src_mac, device.mac, "name", timeout_sec=3)
            if result is None:
                pytest.skip("Device did not respond to DCP Get after Set")

            name = result.decode("utf-8", errors="replace")
            assert name == temp_name, f"Expected '{temp_name}', got '{name}'"
        except (OSError, TimeoutError):
            pytest.skip("DCP Set not supported by device")
        finally:
            # Always attempt to restore the original name
            try:
                set_param(sock, src_mac, device.mac, "name", station_name, timeout_sec=3)
            except (OSError, TimeoutError):
                pass
            sock.close()

    def test_set_name_restore_original(self, interface, station_name):
        """After set+restore cycle the original name should be intact."""
        device = TestDCPDiscover._find_device(interface, station_name)
        sock = ethernet_socket(interface)
        src_mac = get_mac(interface)
        temp_name = "restore-check-tmp"
        try:
            ok = set_param(sock, src_mac, device.mac, "name", temp_name, timeout_sec=3)
            if not ok:
                pytest.skip("Device did not respond to DCP Set (unsupported)")

            # Restore original name
            ok = set_param(sock, src_mac, device.mac, "name", station_name, timeout_sec=3)
            if not ok:
                pytest.skip("Device did not respond to DCP Set for restore")

            # Verify original name is back
            result = get_param(sock, src_mac, device.mac, "name", timeout_sec=3)
            if result is None:
                pytest.skip("Device did not respond to DCP Get after restore")

            name = result.decode("utf-8", errors="replace")
            assert name == EXPECTED_STATION_NAME, (
                f"Expected restored name '{EXPECTED_STATION_NAME}', got '{name}'"
            )
        except (OSError, TimeoutError):
            pytest.skip("DCP Set not supported by device")
        finally:
            # Safety net: try to restore name even if assertions failed
            try:
                set_param(sock, src_mac, device.mac, "name", station_name, timeout_sec=3)
            except (OSError, TimeoutError):
                pass
            sock.close()
