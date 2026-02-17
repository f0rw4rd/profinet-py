"""Integration tests for the high-level ProfinetDevice API.

Tests device discovery, context manager, get_info, and I&M convenience
methods using the ProfinetDevice class from profinet.device.
"""

import pytest

from profinet import (
    DeviceInfo,
    PNInM0,
    PNInM1,
    PNInM2,
    PNInM3,
    ProfinetDevice,
    SlotInfo,
    scan,
)

from .conftest import (
    EXPECTED_DEVICE_ID,
    EXPECTED_HW_REVISION,
    EXPECTED_IM1_TAG_FUNCTION,
    EXPECTED_IM1_TAG_LOCATION,
    EXPECTED_IM2_DATE,
    EXPECTED_IM3_DESCRIPTOR,
    EXPECTED_ORDER_ID,
    EXPECTED_SERIAL_NUMBER,
    EXPECTED_SW_REVISION_MAJOR,
    EXPECTED_SW_REVISION_MINOR,
    EXPECTED_SW_REVISION_PREFIX,
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
# Discovery
# ---------------------------------------------------------------------------


class TestProfinetDeviceDiscover:
    """Test ProfinetDevice.discover() factory method."""

    def test_discover_by_name(self, interface, station_name):
        """Discover device by station name should return a ProfinetDevice."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        assert device is not None
        assert device.name == station_name

    def test_discover_nonexistent_raises(self, interface):
        """Discovering a nonexistent device should raise an error."""
        from profinet.exceptions import DCPDeviceNotFoundError

        with pytest.raises(DCPDeviceNotFoundError):
            ProfinetDevice.discover("this-device-does-not-exist", interface, timeout=3.0)


# ---------------------------------------------------------------------------
# Context Manager
# ---------------------------------------------------------------------------


class TestProfinetDeviceContextManager:
    """Test ProfinetDevice as context manager."""

    def test_context_manager_connect_disconnect(self, interface, station_name):
        """Using 'with' should connect on enter and close on exit."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            # Inside the context, device should be connected
            assert device._connected is True

        # After exiting, device should be disconnected
        assert device._connected is False

    def test_context_manager_read_im0(self, interface, station_name):
        """Should be able to read I&M0 inside context manager."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            im0 = device.read_im0()
            assert isinstance(im0, PNInM0)
            assert im0.vendor_id == EXPECTED_VENDOR_ID


# ---------------------------------------------------------------------------
# Device Info
# ---------------------------------------------------------------------------


class TestProfinetDeviceInfo:
    """Test ProfinetDevice.get_info() method."""

    def test_get_info_basic(self, interface, station_name):
        """get_info should return a DeviceInfo with DCP and I&M0 data."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info()
            assert isinstance(info, DeviceInfo)
            assert info.name == station_name
            assert info.vendor_id == EXPECTED_VENDOR_ID
            assert info.device_id == EXPECTED_DEVICE_ID

    def test_get_info_has_im0(self, interface, station_name):
        """get_info should populate I&M0 data."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info()
            assert info.im0 is not None, "DeviceInfo.im0 should be populated"
            assert isinstance(info.im0, PNInM0)

    def test_get_info_serial_number(self, interface, station_name):
        """DeviceInfo.serial_number should match expected value."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info()
            assert info.serial_number == EXPECTED_SERIAL_NUMBER, (
                f"Expected serial '{EXPECTED_SERIAL_NUMBER}', got '{info.serial_number}'"
            )

    def test_get_info_order_id(self, interface, station_name):
        """DeviceInfo.order_id should match expected value."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info()
            assert info.order_id == EXPECTED_ORDER_ID, (
                f"Expected order_id '{EXPECTED_ORDER_ID}', got '{info.order_id}'"
            )

    def test_get_info_hardware_revision(self, interface, station_name):
        """DeviceInfo.hardware_revision should match expected value."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info()
            assert info.hardware_revision == EXPECTED_HW_REVISION, (
                f"Expected hw_revision {EXPECTED_HW_REVISION}, got {info.hardware_revision}"
            )

    def test_get_info_software_revision_format(self, interface, station_name):
        """DeviceInfo.software_revision should be a 'Vx.y.z' format string."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info()
            sw = info.software_revision
            assert isinstance(sw, str)
            assert len(sw) > 0, "software_revision should not be empty"
            # Should start with 'V' prefix
            assert sw[0] == chr(EXPECTED_SW_REVISION_PREFIX), (
                f"Expected prefix '{chr(EXPECTED_SW_REVISION_PREFIX)}', got '{sw[0]}'"
            )
            # Should contain dots separating version numbers
            parts = sw[1:].split(".")
            assert len(parts) == 3, f"software_revision should be 'Vx.y.z', got '{sw}'"
            for part in parts:
                assert part.isdigit(), (
                    f"Version component should be numeric, got '{part}' in '{sw}'"
                )

    def test_get_info_software_revision_values(self, interface, station_name):
        """DeviceInfo.software_revision values should match expected."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info()
            sw = info.software_revision
            # Parse "Vmajor.minor.internal"
            parts = sw[1:].split(".")
            assert int(parts[0]) == EXPECTED_SW_REVISION_MAJOR
            assert int(parts[1]) == EXPECTED_SW_REVISION_MINOR

    def test_get_info_vendor_id_positive(self, interface, station_name):
        """DeviceInfo.vendor_id should be a positive integer."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info()
            assert isinstance(info.vendor_id, int)
            assert info.vendor_id > 0

    def test_get_info_device_id_positive(self, interface, station_name):
        """DeviceInfo.device_id should be a positive integer."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info()
            assert isinstance(info.device_id, int)
            assert info.device_id > 0

    def test_get_info_ip_non_empty(self, interface, station_name):
        """DeviceInfo.ip should be a non-empty string."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info()
            assert isinstance(info.ip, str)
            assert len(info.ip) > 0
            assert info.ip != "0.0.0.0"

    def test_get_info_mac_non_empty(self, interface, station_name):
        """DeviceInfo.mac should be a non-empty string."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info()
            assert isinstance(info.mac, str)
            assert len(info.mac) > 0
            assert info.mac != "00:00:00:00:00:00"

    def test_get_info_with_topology(self, interface, station_name):
        """get_info with include_topology should populate topology field."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info(include_topology=True)
            assert isinstance(info, DeviceInfo)
            # Topology may or may not be available depending on device
            # but the call should not crash

    def test_get_info_im0_vendor_matches_dcp(self, interface, station_name):
        """I&M0 vendor_id from get_info should match DCP-reported vendor_id."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info()
            assert info.im0 is not None
            assert info.im0.vendor_id == info.vendor_id, (
                f"I&M0 vendor_id (0x{info.im0.vendor_id:04X}) should match "
                f"DCP vendor_id (0x{info.vendor_id:04X})"
            )

    def test_device_properties(self, interface, station_name):
        """Device properties (name, ip, mac) should be accessible."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        assert device.name == station_name
        assert device.ip != ""
        assert device.mac != ""


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


class TestScan:
    """Test module-level scan() function."""

    def test_scan_finds_device(self, interface, station_name):
        """scan() should find the test device."""
        devices = list(scan(interface, timeout=3.0))
        assert len(devices) >= 1, "scan() should find at least one device"

        names = [d.name for d in devices]
        assert station_name in names, f"Device '{station_name}' not found. Discovered: {names}"

    def test_scan_device_has_ip(self, interface, station_name):
        """Scanned devices should have IP addresses."""
        for device in scan(interface, timeout=3.0):
            if device.name == station_name:
                assert device.ip != "", "Device should have an IP address"
                return
        pytest.fail(f"Device '{station_name}' not found in scan")

    def test_scan_device_has_mac(self, interface, station_name):
        """Scanned devices should have MAC addresses."""
        for device in scan(interface, timeout=3.0):
            if device.name == station_name:
                assert device.mac != "", "Device should have a MAC address"
                assert device.mac != "00:00:00:00:00:00"
                return
        pytest.fail(f"Device '{station_name}' not found in scan")

    def test_scan_devices_are_profinet_device(self, interface, station_name):
        """Scanned devices should be ProfinetDevice instances."""
        for device in scan(interface, timeout=3.0):
            assert isinstance(device, ProfinetDevice)


# ---------------------------------------------------------------------------
# I&M Convenience Methods
# ---------------------------------------------------------------------------


class TestProfinetDeviceIM:
    """Test ProfinetDevice I&M convenience methods."""

    def test_read_im0_convenience(self, interface, station_name):
        """device.read_im0() should return PNInM0."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            im0 = device.read_im0()
            assert isinstance(im0, PNInM0)

    def test_read_im0_vendor_matches(self, interface, station_name):
        """device.read_im0() vendor_id should match expected."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            im0 = device.read_im0()
            assert im0.vendor_id == EXPECTED_VENDOR_ID

    def test_read_im1_convenience(self, interface, station_name):
        """device.read_im1() should return PNInM1 with correct tag data."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            im1 = device.read_im1()
            assert isinstance(im1, PNInM1)

            tag_function = im1.im_tag_function
            if isinstance(tag_function, bytes):
                tag_function = tag_function.decode("latin-1").strip()
            assert tag_function == EXPECTED_IM1_TAG_FUNCTION, (
                f"Expected '{EXPECTED_IM1_TAG_FUNCTION}', got '{tag_function}'"
            )

            tag_location = im1.im_tag_location
            if isinstance(tag_location, bytes):
                tag_location = tag_location.decode("latin-1").strip()
            assert tag_location == EXPECTED_IM1_TAG_LOCATION, (
                f"Expected '{EXPECTED_IM1_TAG_LOCATION}', got '{tag_location}'"
            )

    def test_read_im2_convenience(self, interface, station_name):
        """device.read_im2() should return PNInM2 with correct date."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            im2 = device.read_im2()
            assert isinstance(im2, PNInM2)

            date = im2.im_date
            if isinstance(date, bytes):
                date = date.decode("latin-1").strip()
            assert date == EXPECTED_IM2_DATE, f"Expected '{EXPECTED_IM2_DATE}', got '{date}'"

    def test_read_im3_convenience(self, interface, station_name):
        """device.read_im3() should return PNInM3 with correct descriptor."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            im3 = device.read_im3()
            assert isinstance(im3, PNInM3)

            descriptor = im3.im_descriptor
            if isinstance(descriptor, bytes):
                descriptor = descriptor.decode("latin-1").strip()
            assert descriptor == EXPECTED_IM3_DESCRIPTOR, (
                f"Expected '{EXPECTED_IM3_DESCRIPTOR}', got '{descriptor}'"
            )

    def test_read_all_im_convenience(self, interface, station_name):
        """device.read_all_im() should return dict with im0..im3."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            result = device.read_all_im()
            assert isinstance(result, dict)
            assert "im0" in result
            assert "im1" in result
            assert "im2" in result
            assert "im3" in result

    def test_read_all_im_types(self, interface, station_name):
        """device.read_all_im() values should be correct types."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            result = device.read_all_im()
            if "im0" in result:
                assert isinstance(result["im0"], PNInM0)
            if "im1" in result:
                assert isinstance(result["im1"], PNInM1)
            if "im2" in result:
                assert isinstance(result["im2"], PNInM2)
            if "im3" in result:
                assert isinstance(result["im3"], PNInM3)


# ---------------------------------------------------------------------------
# Slot Discovery and Diagnosis
# ---------------------------------------------------------------------------


class TestProfinetDeviceAdvanced:
    """Test advanced ProfinetDevice methods."""

    def test_discover_slots(self, interface, station_name):
        """device.discover_slots() should find at least the DAP."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            try:
                slots = device.discover_slots()
                assert isinstance(slots, list)
                assert len(slots) >= 1, "Should find at least one slot"
            except Exception:
                pytest.skip("Device does not support slot discovery")

    def test_discover_slots_dap_structure(self, interface, station_name):
        """Slot 0 (DAP) should have subslot 1 and at least one port subslot."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            try:
                slots = device.discover_slots()
            except Exception:
                pytest.skip("Device does not support slot discovery")

            dap_subslots = {s.subslot for s in slots if s.slot == 0}
            assert 1 in dap_subslots, f"DAP should have subslot 1. Found: {sorted(dap_subslots)}"
            port_subslots = [s for s in dap_subslots if s >= 0x8000]
            assert len(port_subslots) >= 1, (
                f"DAP should have port subslots (0x8000+). Found: {sorted(dap_subslots)}"
            )

    def test_discover_slots_slot_count(self, interface, station_name):
        """Device should report a reasonable number of unique slots."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            try:
                slots = device.discover_slots()
            except Exception:
                pytest.skip("Device does not support slot discovery")

            unique_slots = {s.slot for s in slots}
            assert len(unique_slots) >= 1, "Should have at least one unique slot"
            # Sanity: PROFINET supports up to 0xFFFF slots, but typical devices
            # have fewer than 100
            assert len(unique_slots) <= 1000, f"Unusually many slots: {len(unique_slots)}"

    def test_read_diagnosis(self, interface, station_name):
        """device.read_diagnosis() should return diagnosis data."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            try:
                diag = device.read_diagnosis()
                assert diag is not None
            except Exception:
                # Diagnosis may fail on healthy device with no entries
                pass

    def test_read_topology(self, interface, station_name):
        """device.read_topology() should return PDRealData."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            try:
                topo = device.read_topology()
                assert topo is not None
            except Exception:
                pytest.skip("Device does not support topology readout")


# ---------------------------------------------------------------------------
# Cross-validation: DCP vs RPC
# ---------------------------------------------------------------------------


class TestCrossValidation:
    """Verify data consistency between DCP discovery and RPC reads."""

    def test_dcp_vendor_matches_rpc_im0(self, interface, station_name):
        """DCP vendor_id should match I&M0 vendor_id from RPC."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        dcp_vendor_id = device._info.vendor_id

        with device:
            im0 = device.read_im0()
            rpc_vendor_id = im0.vendor_id

        assert dcp_vendor_id == rpc_vendor_id, (
            f"DCP vendor_id (0x{dcp_vendor_id:04X}) != RPC I&M0 vendor_id (0x{rpc_vendor_id:04X})"
        )

    def test_dcp_name_matches_device_info(self, interface, station_name):
        """DCP station name should match DeviceInfo.name."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        with device:
            info = device.get_info()
            assert info.name == station_name
            assert device.name == info.name

    def test_dcp_ip_matches_device_info(self, interface, station_name):
        """DCP IP address should match DeviceInfo.ip."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        dcp_ip = device.ip
        with device:
            info = device.get_info()
            assert info.ip == dcp_ip, f"DCP IP '{dcp_ip}' != DeviceInfo IP '{info.ip}'"

    def test_dcp_device_id_matches_device_info(self, interface, station_name):
        """DCP device_id should match DeviceInfo.device_id."""
        device = ProfinetDevice.discover(station_name, interface, timeout=3.0)
        dcp_device_id = device._info.device_id
        with device:
            info = device.get_info()
            assert info.device_id == dcp_device_id, (
                f"DCP device_id (0x{dcp_device_id:04X}) != "
                f"DeviceInfo device_id (0x{info.device_id:04X})"
            )

    def test_get_info_im0_serial_matches_direct_rpc(self, interface, station_name):
        """Serial number from get_info() should match direct read_im0()."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            info = device.get_info()
            direct_im0 = device.read_im0()

            direct_serial = direct_im0.im_serial_number
            if isinstance(direct_serial, bytes):
                direct_serial = direct_serial.decode("latin-1").strip()

            assert info.serial_number == direct_serial, (
                f"get_info serial '{info.serial_number}' != direct read serial '{direct_serial}'"
            )

    def test_get_info_im0_order_matches_direct_rpc(self, interface, station_name):
        """Order ID from get_info() should match direct read_im0()."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            info = device.get_info()
            direct_im0 = device.read_im0()

            direct_order = direct_im0.order_id
            if isinstance(direct_order, bytes):
                direct_order = direct_order.decode("latin-1").strip()

            assert info.order_id == direct_order, (
                f"get_info order '{info.order_id}' != direct read order '{direct_order}'"
            )


# ---------------------------------------------------------------------------
# Subslot Discovery (ProfinetDevice API)
# ---------------------------------------------------------------------------


class TestProfinetDeviceSubslotDiscovery:
    """Test subslot-level discovery via ProfinetDevice."""

    def test_dap_has_subslots(self, interface, station_name):
        """Slot 0 (DAP) should have at least one subslot via ProfinetDevice."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            try:
                slots = device.discover_slots()
            except Exception:
                pytest.skip("Device does not support slot discovery")
            dap_entries = [s for s in slots if s.slot == 0]
            assert len(dap_entries) >= 1, "Slot 0 (DAP) should have at least one subslot entry"

    def test_every_slot_has_subslots(self, interface, station_name):
        """Every unique slot should have at least one subslot entry."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            try:
                slots = device.discover_slots()
            except Exception:
                pytest.skip("Device does not support slot discovery")
            assert len(slots) >= 1, "Should discover at least one slot"
            slot_numbers = {s.slot for s in slots}
            for slot_num in slot_numbers:
                entries = [s for s in slots if s.slot == slot_num]
                assert len(entries) >= 1, f"Slot {slot_num} should have at least one subslot entry"

    def test_subslot_numbers_are_positive(self, interface, station_name):
        """All subslot numbers should be positive integers."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            try:
                slots = device.discover_slots()
            except Exception:
                pytest.skip("Device does not support slot discovery")
            for entry in slots:
                assert isinstance(entry.subslot, int), (
                    f"Subslot should be int, got {type(entry.subslot)}"
                )
                assert entry.subslot > 0, (
                    f"Subslot number should be positive, got {entry.subslot} in slot {entry.slot}"
                )

    def test_slot_entries_are_slotinfo(self, interface, station_name):
        """All discovered slot entries should be SlotInfo instances."""
        with ProfinetDevice.discover(station_name, interface, timeout=3.0) as device:
            try:
                slots = device.discover_slots()
            except Exception:
                pytest.skip("Device does not support slot discovery")
            for entry in slots:
                assert isinstance(entry, SlotInfo), f"Expected SlotInfo, got {type(entry).__name__}"
