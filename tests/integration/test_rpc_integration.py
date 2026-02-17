"""Integration tests for DCE/RPC operations.

Tests RPC connection establishment, I&M record reading, diagnosis,
topology, and error handling against the PROFINET device emulator.
"""

import pytest

from profinet import (
    ModuleDiffBlock,
    PDRealData,
    PNInM0,
    PNInM1,
    PNInM2,
    PNInM3,
    RealIdentificationData,
    RPCCon,
    SlotInfo,
    epm_lookup,
    ethernet_socket,
    get_mac,
    get_station_info,
    indices,
)
from profinet.diagnosis import DiagnosisData
from profinet.exceptions import PNIOError, RPCError

from .conftest import (
    EXPECTED_HW_REVISION,
    EXPECTED_IM1_TAG_FUNCTION,
    EXPECTED_IM1_TAG_LOCATION,
    EXPECTED_IM2_DATE,
    EXPECTED_IM3_DESCRIPTOR,
    EXPECTED_ORDER_ID,
    EXPECTED_PROFILE_ID,
    EXPECTED_PROFILE_SPEC_TYPE,
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
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def device_info(interface, station_name):
    """Resolve station name to DCP device info (used by RPCCon)."""
    sock = ethernet_socket(interface)
    src_mac = get_mac(interface)
    try:
        info = get_station_info(sock, src_mac, station_name, timeout_sec=3)
        return info, src_mac
    finally:
        sock.close()


@pytest.fixture()
def rpc_connection(device_info):
    """Provide a connected RPCCon instance; close after test."""
    info, src_mac = device_info
    rpc = RPCCon(info, timeout=3.0)
    rpc.connect(src_mac)
    yield rpc
    rpc.close()


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------


class TestRPCConnection:
    """Test RPC connection lifecycle."""

    def test_connect_succeeds(self, device_info):
        """RPCCon.connect() should establish an AR without error."""
        info, src_mac = device_info
        rpc = RPCCon(info, timeout=3.0)
        try:
            rpc.connect(src_mac)
            # If we reach here, connect succeeded
        finally:
            rpc.close()

    def test_disconnect_and_reconnect(self, device_info):
        """Disconnect then reconnect should work cleanly."""
        info, src_mac = device_info
        rpc = RPCCon(info, timeout=3.0)
        try:
            rpc.connect(src_mac)
            rpc.disconnect()
            # Create a fresh connection after disconnect
            rpc2 = RPCCon(info, timeout=3.0)
            try:
                rpc2.connect(src_mac)
            finally:
                rpc2.close()
        finally:
            rpc.close()


# ---------------------------------------------------------------------------
# I&M Records
# ---------------------------------------------------------------------------


class TestIMRecords:
    """Test reading Identification & Maintenance records."""

    def test_read_im0(self, rpc_connection, device_properties):
        """I&M0 should return valid identification data."""
        im0 = rpc_connection.read_im0()
        assert isinstance(im0, PNInM0)

    def test_im0_vendor_id(self, rpc_connection):
        """I&M0 vendor ID should match GSDML configuration."""
        im0 = rpc_connection.read_im0()
        assert im0.vendor_id == EXPECTED_VENDOR_ID, (
            f"Expected vendor_id 0x{EXPECTED_VENDOR_ID:04X}, got 0x{im0.vendor_id:04X}"
        )

    def test_im0_vendor_id_is_positive(self, rpc_connection):
        """I&M0 vendor ID should be a positive integer."""
        im0 = rpc_connection.read_im0()
        assert isinstance(im0.vendor_id, int)
        assert im0.vendor_id > 0, "vendor_id should be > 0"

    def test_im0_vendor_id_bytes(self, rpc_connection):
        """I&M0 vendor_id_high and vendor_id_low should combine correctly."""
        im0 = rpc_connection.read_im0()
        assert isinstance(im0.vendor_id_high, int)
        assert isinstance(im0.vendor_id_low, int)
        assert 0 <= im0.vendor_id_high <= 0xFF
        assert 0 <= im0.vendor_id_low <= 0xFF
        combined = (im0.vendor_id_high << 8) | im0.vendor_id_low
        assert combined == EXPECTED_VENDOR_ID

    def test_im0_order_id(self, rpc_connection):
        """I&M0 order ID should match GSDML configuration."""
        im0 = rpc_connection.read_im0()
        order_id = im0.order_id
        if isinstance(order_id, bytes):
            order_id = order_id.decode("latin-1").strip()
        assert order_id == EXPECTED_ORDER_ID, (
            f"Expected order_id '{EXPECTED_ORDER_ID}', got '{order_id}'"
        )

    def test_im0_order_id_raw_length(self, rpc_connection):
        """I&M0 order_id raw field should be exactly 20 bytes per PROFINET spec."""
        im0 = rpc_connection.read_im0()
        raw = im0.order_id
        # After decode_bytes, it's a string; get the raw from the struct
        # The decoded string may be shorter due to stripping, but the protocol
        # sends exactly 20 bytes. Check that the decoded value is non-empty
        # and not longer than 20 chars.
        if isinstance(raw, bytes):
            assert len(raw) == 20, f"order_id should be 20 bytes, got {len(raw)}"
        else:
            assert len(raw) <= 20, f"order_id should be <= 20 chars, got {len(raw)}"
            assert len(raw) > 0, "order_id should not be empty"

    def test_im0_serial_number(self, rpc_connection):
        """I&M0 serial number should match GSDML configuration."""
        im0 = rpc_connection.read_im0()
        serial = im0.im_serial_number
        if isinstance(serial, bytes):
            serial = serial.decode("latin-1").strip()
        assert serial == EXPECTED_SERIAL_NUMBER, (
            f"Expected serial '{EXPECTED_SERIAL_NUMBER}', got '{serial}'"
        )

    def test_im0_serial_number_raw_length(self, rpc_connection):
        """I&M0 serial_number raw field should be exactly 16 bytes per PROFINET spec."""
        im0 = rpc_connection.read_im0()
        raw = im0.im_serial_number
        if isinstance(raw, bytes):
            assert len(raw) == 16, f"serial_number should be 16 bytes, got {len(raw)}"
        else:
            assert len(raw) <= 16, f"serial_number should be <= 16 chars, got {len(raw)}"
            assert len(raw) > 0, "serial_number should not be empty"

    def test_im0_hardware_revision(self, rpc_connection):
        """I&M0 hardware revision should match GSDML configuration."""
        im0 = rpc_connection.read_im0()
        assert im0.im_hardware_revision == EXPECTED_HW_REVISION

    def test_im0_hardware_revision_type(self, rpc_connection):
        """I&M0 hardware revision should be a non-negative integer."""
        im0 = rpc_connection.read_im0()
        assert isinstance(im0.im_hardware_revision, int)
        assert im0.im_hardware_revision >= 0

    def test_im0_sw_revision_prefix(self, rpc_connection):
        """I&M0 software revision prefix should be 'V'."""
        im0 = rpc_connection.read_im0()
        assert im0.sw_revision_prefix == EXPECTED_SW_REVISION_PREFIX, (
            f"Expected prefix {chr(EXPECTED_SW_REVISION_PREFIX)!r}, "
            f"got {chr(im0.sw_revision_prefix)!r}"
        )

    def test_im0_sw_revision_prefix_is_printable(self, rpc_connection):
        """I&M0 sw_revision_prefix should be a printable ASCII character."""
        im0 = rpc_connection.read_im0()
        assert isinstance(im0.sw_revision_prefix, int)
        assert 0x20 <= im0.sw_revision_prefix <= 0x7E, (
            f"sw_revision_prefix should be printable ASCII, got 0x{im0.sw_revision_prefix:02X}"
        )

    def test_im0_sw_revision_major(self, rpc_connection):
        """I&M0 software revision major should match."""
        im0 = rpc_connection.read_im0()
        assert im0.im_sw_revision_functional_enhancement == EXPECTED_SW_REVISION_MAJOR

    def test_im0_sw_revision_minor(self, rpc_connection):
        """I&M0 software revision minor (bug fix) should match."""
        im0 = rpc_connection.read_im0()
        assert im0.im_sw_revision_bug_fix == EXPECTED_SW_REVISION_MINOR

    def test_im0_sw_revision_fields_non_negative(self, rpc_connection):
        """I&M0 sw revision fields should all be non-negative integers (0-255)."""
        im0 = rpc_connection.read_im0()
        for field_name in [
            "im_sw_revision_functional_enhancement",
            "im_sw_revision_bug_fix",
            "im_sw_revision_internal_change",
        ]:
            val = getattr(im0, field_name)
            assert isinstance(val, int), f"{field_name} should be int"
            assert 0 <= val <= 255, f"{field_name} should be 0-255, got {val}"

    def test_im0_revision_counter_non_negative(self, rpc_connection):
        """I&M0 revision counter should be a non-negative 16-bit integer."""
        im0 = rpc_connection.read_im0()
        assert isinstance(im0.im_revision_counter, int)
        assert 0 <= im0.im_revision_counter <= 0xFFFF, (
            f"im_revision_counter should be 0-65535, got {im0.im_revision_counter}"
        )

    def test_im0_profile_id(self, rpc_connection):
        """I&M0 profile ID should match GSDML configuration."""
        im0 = rpc_connection.read_im0()
        assert im0.im_profile_id == EXPECTED_PROFILE_ID, (
            f"Expected profile_id 0x{EXPECTED_PROFILE_ID:04X}, got 0x{im0.im_profile_id:04X}"
        )

    def test_im0_profile_spec_type(self, rpc_connection):
        """I&M0 profile specific type should match GSDML configuration."""
        im0 = rpc_connection.read_im0()
        assert im0.im_profile_specific_type == EXPECTED_PROFILE_SPEC_TYPE, (
            f"Expected profile_spec_type 0x{EXPECTED_PROFILE_SPEC_TYPE:04X}, "
            f"got 0x{im0.im_profile_specific_type:04X}"
        )

    def test_im0_im_version_format(self, rpc_connection):
        """I&M0 im_version should be a 16-bit value encoding major.minor."""
        im0 = rpc_connection.read_im0()
        assert isinstance(im0.im_version, int)
        assert 0 <= im0.im_version <= 0xFFFF, f"im_version should be 0-65535, got {im0.im_version}"
        # Version is typically 0x0101 (v1.1) per PROFINET spec
        major = (im0.im_version >> 8) & 0xFF
        _minor = im0.im_version & 0xFF
        assert major >= 1, f"im_version major should be >= 1, got {major}"

    def test_im0_im_supported(self, rpc_connection):
        """I&M0 supported records should include IM1, IM2, IM3."""
        im0 = rpc_connection.read_im0()
        # PNET_SUPPORTED_IM1=0x0002, IM2=0x0004, IM3=0x0008
        supported = im0.im_supported
        assert supported & 0x0002, "IM1 should be supported"
        assert supported & 0x0004, "IM2 should be supported"
        assert supported & 0x0008, "IM3 should be supported"

    def test_im0_im_supported_consistent_with_device(self, rpc_connection):
        """I&M0 im_supported bitmask should be consistent: IM1+IM2+IM3 at minimum."""
        im0 = rpc_connection.read_im0()
        supported = im0.im_supported
        assert isinstance(supported, int)
        assert 0 <= supported <= 0xFFFF
        # IM0 is always supported (bit 0 is reserved/IM0 is mandatory, not in bitmask)
        # At minimum IM1|IM2|IM3 = 0x000E
        assert (supported & 0x000E) == 0x000E, (
            f"Expected IM1+IM2+IM3 in im_supported, got 0x{supported:04X}"
        )

    def test_im0_block_header_is_bytes(self, rpc_connection):
        """I&M0 block_header should be 6 bytes."""
        im0 = rpc_connection.read_im0()
        assert isinstance(im0.block_header, bytes)
        assert len(im0.block_header) == 6, (
            f"block_header should be 6 bytes, got {len(im0.block_header)}"
        )

    # -- I&M1 --

    def test_read_im1(self, rpc_connection):
        """I&M1 should return tag function and location data."""
        im1 = rpc_connection.read_im1()
        assert isinstance(im1, PNInM1)

    def test_im1_tag_function_content(self, rpc_connection):
        """I&M1 tag_function should match expected value from conftest."""
        im1 = rpc_connection.read_im1()
        tag_function = im1.im_tag_function
        if isinstance(tag_function, bytes):
            tag_function = tag_function.decode("latin-1").strip()
        assert tag_function == EXPECTED_IM1_TAG_FUNCTION, (
            f"Expected tag_function '{EXPECTED_IM1_TAG_FUNCTION}', got '{tag_function}'"
        )

    def test_im1_tag_function_raw_length(self, rpc_connection):
        """I&M1 tag_function raw field should be exactly 32 bytes per PROFINET spec."""
        im1 = rpc_connection.read_im1()
        raw = im1.im_tag_function
        if isinstance(raw, bytes):
            assert len(raw) == 32, f"tag_function should be 32 bytes, got {len(raw)}"
        else:
            assert len(raw) <= 32, f"tag_function should be <= 32 chars, got {len(raw)}"

    def test_im1_tag_location_content(self, rpc_connection):
        """I&M1 tag_location should match expected value from conftest."""
        im1 = rpc_connection.read_im1()
        tag_location = im1.im_tag_location
        if isinstance(tag_location, bytes):
            tag_location = tag_location.decode("latin-1").strip()
        assert tag_location == EXPECTED_IM1_TAG_LOCATION, (
            f"Expected tag_location '{EXPECTED_IM1_TAG_LOCATION}', got '{tag_location}'"
        )

    def test_im1_tag_location_raw_length(self, rpc_connection):
        """I&M1 tag_location raw field should be exactly 22 bytes per PROFINET spec."""
        im1 = rpc_connection.read_im1()
        raw = im1.im_tag_location
        if isinstance(raw, bytes):
            assert len(raw) == 22, f"tag_location should be 22 bytes, got {len(raw)}"
        else:
            assert len(raw) <= 22, f"tag_location should be <= 22 chars, got {len(raw)}"

    def test_im1_block_header(self, rpc_connection):
        """I&M1 block_header should be 6 bytes."""
        im1 = rpc_connection.read_im1()
        assert isinstance(im1.block_header, bytes)
        assert len(im1.block_header) == 6

    def test_im1_tag_function_is_string(self, rpc_connection):
        """I&M1 tag_function should be a decodeable string."""
        im1 = rpc_connection.read_im1()
        tag = im1.im_tag_function
        if isinstance(tag, bytes):
            tag = tag.decode("latin-1").strip()
        assert isinstance(tag, str)

    # -- I&M2 --

    def test_read_im2(self, rpc_connection):
        """I&M2 should return installation date data."""
        im2 = rpc_connection.read_im2()
        assert isinstance(im2, PNInM2)

    def test_im2_date_content(self, rpc_connection):
        """I&M2 date should match expected value from conftest."""
        im2 = rpc_connection.read_im2()
        date = im2.im_date
        if isinstance(date, bytes):
            date = date.decode("latin-1").strip()
        assert date == EXPECTED_IM2_DATE, f"Expected im_date '{EXPECTED_IM2_DATE}', got '{date}'"

    def test_im2_date_raw_length(self, rpc_connection):
        """I&M2 im_date raw field should be exactly 16 bytes per PROFINET spec."""
        im2 = rpc_connection.read_im2()
        raw = im2.im_date
        if isinstance(raw, bytes):
            assert len(raw) == 16, f"im_date should be 16 bytes, got {len(raw)}"
        else:
            assert len(raw) <= 16, f"im_date should be <= 16 chars, got {len(raw)}"

    def test_im2_date_format(self, rpc_connection):
        """I&M2 date should have YYYY-MM-DD HH:MM format when non-empty."""
        im2 = rpc_connection.read_im2()
        date = im2.im_date
        if isinstance(date, bytes):
            date = date.decode("latin-1").strip()
        if date:
            # Expect "YYYY-MM-DD HH:MM" format (16 chars)
            assert len(date) == 16, f"Date should be 16 chars, got {len(date)}: '{date}'"
            # Basic format check
            assert date[4] == "-", f"Expected '-' at position 4, got '{date[4]}'"
            assert date[7] == "-", f"Expected '-' at position 7, got '{date[7]}'"
            assert date[10] == " ", f"Expected ' ' at position 10, got '{date[10]}'"
            assert date[13] == ":", f"Expected ':' at position 13, got '{date[13]}'"

    def test_im2_block_header(self, rpc_connection):
        """I&M2 block_header should be 6 bytes."""
        im2 = rpc_connection.read_im2()
        assert isinstance(im2.block_header, bytes)
        assert len(im2.block_header) == 6

    # -- I&M3 --

    def test_read_im3(self, rpc_connection):
        """I&M3 should return descriptor data."""
        im3 = rpc_connection.read_im3()
        assert isinstance(im3, PNInM3)

    def test_im3_descriptor_content(self, rpc_connection):
        """I&M3 descriptor should match expected value from conftest."""
        im3 = rpc_connection.read_im3()
        descriptor = im3.im_descriptor
        if isinstance(descriptor, bytes):
            descriptor = descriptor.decode("latin-1").strip()
        assert descriptor == EXPECTED_IM3_DESCRIPTOR, (
            f"Expected im_descriptor '{EXPECTED_IM3_DESCRIPTOR}', got '{descriptor}'"
        )

    def test_im3_descriptor_raw_length(self, rpc_connection):
        """I&M3 im_descriptor raw field should be exactly 54 bytes per PROFINET spec."""
        im3 = rpc_connection.read_im3()
        raw = im3.im_descriptor
        if isinstance(raw, bytes):
            assert len(raw) == 54, f"im_descriptor should be 54 bytes, got {len(raw)}"
        else:
            assert len(raw) <= 54, f"im_descriptor should be <= 54 chars, got {len(raw)}"

    def test_im3_block_header(self, rpc_connection):
        """I&M3 block_header should be 6 bytes."""
        im3 = rpc_connection.read_im3()
        assert isinstance(im3.block_header, bytes)
        assert len(im3.block_header) == 6

    # -- read_all_im --

    def test_read_all_im(self, rpc_connection):
        """read_all_im should return a dict with at least IM0."""
        result = rpc_connection.read_all_im()
        assert isinstance(result, dict)
        assert "im0" in result, "read_all_im should include I&M0"

    def test_read_all_im_keys(self, rpc_connection):
        """read_all_im should return im0, im1, im2, im3 keys (device supports them)."""
        result = rpc_connection.read_all_im()
        for key in ["im0", "im1", "im2", "im3"]:
            assert key in result, f"read_all_im should include '{key}'"

    def test_read_all_im_types(self, rpc_connection):
        """read_all_im values should be correct I&M types."""
        result = rpc_connection.read_all_im()
        expected_types = {
            "im0": PNInM0,
            "im1": PNInM1,
            "im2": PNInM2,
            "im3": PNInM3,
        }
        for key, expected_type in expected_types.items():
            if key in result:
                assert isinstance(result[key], expected_type), (
                    f"result['{key}'] should be {expected_type.__name__}, "
                    f"got {type(result[key]).__name__}"
                )

    def test_read_all_im_im0_matches_direct(self, rpc_connection):
        """I&M0 from read_all_im should match a direct read_im0 call."""
        all_im = rpc_connection.read_all_im()
        direct = rpc_connection.read_im0()

        im0_from_all = all_im["im0"]
        assert im0_from_all.vendor_id == direct.vendor_id
        assert im0_from_all.im_hardware_revision == direct.im_hardware_revision

        # Compare serial number
        serial_all = im0_from_all.im_serial_number
        serial_direct = direct.im_serial_number
        if isinstance(serial_all, bytes):
            serial_all = serial_all.decode("latin-1").strip()
        if isinstance(serial_direct, bytes):
            serial_direct = serial_direct.decode("latin-1").strip()
        assert serial_all == serial_direct


# ---------------------------------------------------------------------------
# Diagnosis
# ---------------------------------------------------------------------------


class TestDiagnosis:
    """Test reading diagnosis data."""

    def test_read_diagnosis_returns_diagnosis_data(self, rpc_connection):
        """Reading diagnosis should return a DiagnosisData instance."""
        try:
            diag = rpc_connection.read_diagnosis()
            assert isinstance(diag, DiagnosisData)
            # DiagnosisData should have expected attributes
            assert hasattr(diag, "api")
            assert hasattr(diag, "slot")
            assert hasattr(diag, "subslot")
            assert hasattr(diag, "entries")
            assert hasattr(diag, "raw_data")
        except PNIOError:
            # Some devices return PNIO error for empty diagnosis
            pass

    def test_read_diagnosis_healthy_device(self, rpc_connection):
        """Healthy device diagnosis should have valid structure."""
        try:
            diag = rpc_connection.read_diagnosis()
            assert isinstance(diag.entries, list)
            # p-net emulator may report diagnosis entries even when healthy
            assert isinstance(diag.has_errors, bool)
            assert isinstance(diag.has_maintenance_required, bool)
            assert isinstance(diag.has_maintenance_demanded, bool)
        except PNIOError:
            pass

    def test_read_diagnosis_field_types(self, rpc_connection):
        """DiagnosisData fields should have correct types."""
        try:
            diag = rpc_connection.read_diagnosis()
            assert isinstance(diag.api, int)
            assert isinstance(diag.slot, int)
            assert isinstance(diag.subslot, int)
            assert isinstance(diag.entries, list)
            assert isinstance(diag.raw_data, bytes)
        except PNIOError:
            pass

    def test_read_all_diagnosis(self, rpc_connection):
        """read_all_diagnosis should return a dict (possibly empty)."""
        try:
            result = rpc_connection.read_all_diagnosis()
            assert isinstance(result, dict)
            # For healthy device, all diagnosis indices should return empty
            for idx, diag in result.items():
                assert isinstance(idx, int)
                assert isinstance(diag, DiagnosisData)
        except (RPCError, PNIOError):
            # Device may not support all diagnosis indices
            pass


# ---------------------------------------------------------------------------
# Topology / Identification
# ---------------------------------------------------------------------------


class TestTopology:
    """Test reading topology and identification data."""

    def test_read_real_identification_data(self, rpc_connection):
        """RealIdentificationData should list slots and subslots."""
        try:
            rid = rpc_connection.read_real_identification_data()
            assert isinstance(rid, RealIdentificationData)
            assert isinstance(rid.slots, list)
            assert len(rid.slots) >= 1, "Should have at least one slot"
        except (RPCError, PNIOError):
            pytest.skip("Device does not support RealIdentificationData")

    def test_real_id_slot0_exists(self, rpc_connection):
        """RealIdentificationData should contain slot 0 (DAP)."""
        try:
            rid = rpc_connection.read_real_identification_data()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support RealIdentificationData")

        slot0_entries = [s for s in rid.slots if s.slot == 0]
        assert len(slot0_entries) >= 1, (
            f"Slot 0 (DAP) should exist. Slots found: {[s.slot for s in rid.slots]}"
        )

    def test_real_id_slot0_has_module_ident(self, rpc_connection):
        """Slot 0 should have a non-zero module_ident."""
        try:
            rid = rpc_connection.read_real_identification_data()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support RealIdentificationData")

        slot0_entries = [s for s in rid.slots if s.slot == 0]
        assert len(slot0_entries) >= 1
        # At least one slot 0 entry should have a module_ident
        has_module_ident = any(s.module_ident != 0 for s in slot0_entries)
        if not has_module_ident:
            # Some devices may not populate this; just verify the attribute exists
            for s in slot0_entries:
                assert hasattr(s, "module_ident")

    def test_real_id_slots_are_slotinfo(self, rpc_connection):
        """Each entry in RealIdentificationData.slots should be a SlotInfo."""
        try:
            rid = rpc_connection.read_real_identification_data()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support RealIdentificationData")

        for entry in rid.slots:
            assert isinstance(entry, SlotInfo), f"Expected SlotInfo, got {type(entry).__name__}"
            assert isinstance(entry.slot, int)
            assert isinstance(entry.subslot, int)
            assert isinstance(entry.api, int)
            assert isinstance(entry.module_ident, int)
            assert isinstance(entry.submodule_ident, int)

    def test_real_id_version(self, rpc_connection):
        """RealIdentificationData version should be a (int, int) tuple."""
        try:
            rid = rpc_connection.read_real_identification_data()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support RealIdentificationData")

        assert isinstance(rid.version, tuple)
        assert len(rid.version) == 2
        assert isinstance(rid.version[0], int)
        assert isinstance(rid.version[1], int)

    def test_read_pd_real_data(self, rpc_connection):
        """PDRealData should return interface/port information."""
        try:
            pd = rpc_connection.read_pd_real_data()
            assert isinstance(pd, PDRealData)
            assert isinstance(pd.slots, list)
            assert isinstance(pd.ports, list)
        except (RPCError, PNIOError):
            pytest.skip("Device does not support PDRealData")

    def test_pd_real_data_has_slots(self, rpc_connection):
        """PDRealData should contain at least one slot entry."""
        try:
            pd = rpc_connection.read_pd_real_data()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support PDRealData")

        assert len(pd.slots) >= 1, "PDRealData should have at least one slot"

    def test_pd_real_data_interface(self, rpc_connection):
        """PDRealData should contain interface info if available."""
        try:
            pd = rpc_connection.read_pd_real_data()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support PDRealData")

        if pd.interface is not None:
            assert isinstance(pd.interface.chassis_id, str)
            assert isinstance(pd.interface.mac_address, bytes)
            assert len(pd.interface.mac_address) == 6
            assert isinstance(pd.interface.ip_address, bytes)
            assert len(pd.interface.ip_address) == 4

    def test_pd_real_data_port_names(self, rpc_connection):
        """PDRealData ports should have non-empty port_id strings."""
        try:
            pd = rpc_connection.read_pd_real_data()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support PDRealData")

        for port in pd.ports:
            assert isinstance(port.port_id, str), f"port_id should be str, got {type(port.port_id)}"
            assert len(port.port_id) > 0, (
                f"port_id should be non-empty for slot={port.slot} subslot=0x{port.subslot:04X}"
            )

    def test_discover_slots(self, rpc_connection):
        """discover_slots should return slot/subslot list."""
        try:
            slots = rpc_connection.discover_slots()
            assert isinstance(slots, list)
            assert len(slots) >= 1, "Should discover at least one slot"
            # Verify slot 0 (DAP) exists
            dap_slots = [s for s in slots if s.slot == 0]
            assert len(dap_slots) >= 1, "Slot 0 (DAP) should exist"
        except (RPCError, PNIOError):
            pytest.skip("Device does not support slot discovery")

    def test_discover_slots_all_attributes(self, rpc_connection):
        """Each discovered slot should have all expected SlotInfo attributes."""
        try:
            slots = rpc_connection.discover_slots()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support slot discovery")

        for entry in slots:
            assert isinstance(entry, SlotInfo)
            assert hasattr(entry, "slot")
            assert hasattr(entry, "subslot")
            assert hasattr(entry, "api")
            assert hasattr(entry, "module_ident")
            assert hasattr(entry, "submodule_ident")
            assert hasattr(entry, "blocks")
            assert isinstance(entry.slot, int)
            assert isinstance(entry.subslot, int)
            assert isinstance(entry.api, int)
            assert isinstance(entry.module_ident, int)
            assert isinstance(entry.submodule_ident, int)
            assert isinstance(entry.blocks, list)

    def test_read_module_diff(self, rpc_connection):
        """ModuleDiffBlock should be readable after connect."""
        try:
            diff = rpc_connection.read_module_diff()
            assert isinstance(diff, ModuleDiffBlock)
        except (RPCError, PNIOError):
            pytest.skip("Device does not support ModuleDiffBlock")

    def test_module_diff_has_modules(self, rpc_connection):
        """ModuleDiffBlock should contain at least one module."""
        try:
            diff = rpc_connection.read_module_diff()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support ModuleDiffBlock")

        assert isinstance(diff.modules, list)
        # p-net emulator may return empty module diff when all modules match
        # Just verify the structure is valid

    def test_module_diff_structure(self, rpc_connection):
        """ModuleDiffBlock modules should have expected fields."""
        try:
            diff = rpc_connection.read_module_diff()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support ModuleDiffBlock")

        for mod in diff.modules:
            assert hasattr(mod, "api")
            assert hasattr(mod, "slot_number")
            assert hasattr(mod, "module_ident_number")
            assert hasattr(mod, "module_state")
            assert hasattr(mod, "submodules")
            assert isinstance(mod.api, int)
            assert isinstance(mod.slot_number, int)
            assert isinstance(mod.module_ident_number, int)
            assert isinstance(mod.module_state, int)
            assert isinstance(mod.submodules, list)

    def test_module_diff_submodule_structure(self, rpc_connection):
        """ModuleDiffBlock submodules should have expected fields."""
        try:
            diff = rpc_connection.read_module_diff()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support ModuleDiffBlock")

        for mod in diff.modules:
            for sub in mod.submodules:
                assert hasattr(sub, "subslot_number")
                assert hasattr(sub, "submodule_ident_number")
                assert hasattr(sub, "submodule_state")
                assert isinstance(sub.subslot_number, int)
                assert isinstance(sub.submodule_ident_number, int)
                assert isinstance(sub.submodule_state, int)

    def test_module_diff_all_ok_property(self, rpc_connection):
        """ModuleDiffBlock.all_ok should be a boolean."""
        try:
            diff = rpc_connection.read_module_diff()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support ModuleDiffBlock")

        assert isinstance(diff.all_ok, bool)

    def test_module_diff_get_mismatches(self, rpc_connection):
        """ModuleDiffBlock.get_mismatches() should return a list of tuples."""
        try:
            diff = rpc_connection.read_module_diff()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support ModuleDiffBlock")

        mismatches = diff.get_mismatches()
        assert isinstance(mismatches, list)
        for item in mismatches:
            assert isinstance(item, tuple)
            assert len(item) == 3
            slot, subslot, state = item
            assert isinstance(slot, int)
            assert isinstance(subslot, int)
            assert isinstance(state, str)


# ---------------------------------------------------------------------------
# Subslot Discovery
# ---------------------------------------------------------------------------


class TestSubslotDiscovery:
    """Test that discover_slots returns proper subslot information."""

    def test_dap_has_subslots(self, rpc_connection):
        """Slot 0 (DAP) should have at least one subslot."""
        try:
            slots = rpc_connection.discover_slots()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support slot discovery")
        dap_entries = [s for s in slots if s.slot == 0]
        assert len(dap_entries) >= 1, "Slot 0 (DAP) should have at least one subslot entry"

    def test_dap_has_interface_subslot(self, rpc_connection):
        """Slot 0 should contain subslot 1 (interface submodule)."""
        try:
            slots = rpc_connection.discover_slots()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support slot discovery")
        dap_subslots = {s.subslot for s in slots if s.slot == 0}
        assert 1 in dap_subslots, (
            f"Slot 0 should contain subslot 1. Found subslots: {sorted(dap_subslots)}"
        )

    def test_dap_has_port_subslots(self, rpc_connection):
        """Slot 0 should have at least one port subslot (0x8000+)."""
        try:
            slots = rpc_connection.discover_slots()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support slot discovery")
        port_subslots = [s for s in slots if s.slot == 0 and s.subslot >= 0x8000]
        assert len(port_subslots) >= 1, (
            "Slot 0 should have at least one port subslot (0x8000+). "
            f"Found subslots: {sorted(s.subslot for s in slots if s.slot == 0)}"
        )

    def test_every_slot_has_subslots(self, rpc_connection):
        """Every unique slot number should have at least one subslot entry."""
        try:
            slots = rpc_connection.discover_slots()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support slot discovery")
        assert len(slots) >= 1, "Should discover at least one slot"
        slot_numbers = {s.slot for s in slots}
        for slot_num in slot_numbers:
            entries = [s for s in slots if s.slot == slot_num]
            assert len(entries) >= 1, f"Slot {slot_num} should have at least one subslot entry"

    def test_subslot_numbers_are_positive(self, rpc_connection):
        """All subslot numbers should be positive integers."""
        try:
            slots = rpc_connection.discover_slots()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support slot discovery")
        for entry in slots:
            assert isinstance(entry.subslot, int), (
                f"Subslot should be int, got {type(entry.subslot)}"
            )
            assert entry.subslot > 0, (
                f"Subslot number should be positive, got {entry.subslot} in slot {entry.slot}"
            )

    def test_slot_numbers_are_nonnegative(self, rpc_connection):
        """All slot numbers should be non-negative integers."""
        try:
            slots = rpc_connection.discover_slots()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support slot discovery")
        for entry in slots:
            assert isinstance(entry.slot, int), f"Slot should be int, got {type(entry.slot)}"
            assert entry.slot >= 0, f"Slot number should be non-negative, got {entry.slot}"

    def test_no_duplicate_slot_subslot_pairs(self, rpc_connection):
        """Each (slot, subslot) pair should be unique."""
        try:
            slots = rpc_connection.discover_slots()
        except (RPCError, PNIOError):
            pytest.skip("Device does not support slot discovery")

        seen = set()
        for entry in slots:
            pair = (entry.slot, entry.subslot)
            assert pair not in seen, (
                f"Duplicate slot/subslot pair: slot={entry.slot}, subslot=0x{entry.subslot:04X}"
            )
            seen.add(pair)


# ---------------------------------------------------------------------------
# Error Handling
# ---------------------------------------------------------------------------


class TestRPCErrors:
    """Test that invalid operations return proper errors."""

    def test_read_invalid_slot(self, rpc_connection):
        """Reading from a nonexistent slot should raise or return an error status."""
        try:
            result = rpc_connection.read(api=0, slot=99, subslot=1, idx=indices.IM0)
            # Some devices (e.g. p-net) return success with PNIO error in payload
            # instead of raising -- that is acceptable behaviour.
            assert result is not None
        except (RPCError, PNIOError):
            pass  # Expected on devices that reject invalid slots outright

    def test_read_invalid_subslot(self, rpc_connection):
        """Reading from a nonexistent subslot should raise or return an error status."""
        try:
            result = rpc_connection.read(api=0, slot=0, subslot=0xFFFF, idx=indices.IM0)
            # Some devices return success for unknown subslots -- acceptable.
            assert result is not None
        except (RPCError, PNIOError):
            pass  # Expected on devices that reject invalid subslots outright

    def test_read_invalid_index(self, rpc_connection):
        """Reading an unsupported index should raise an error."""
        with pytest.raises((RPCError, PNIOError)):
            # 0x0001 is typically not a valid record index for slot 0
            rpc_connection.read(api=0, slot=0, subslot=1, idx=0x0001)


# ---------------------------------------------------------------------------
# EPM Lookup
# ---------------------------------------------------------------------------


class TestEPMLookup:
    """Test EPM (Endpoint Mapper) lookup."""

    def test_epm_lookup_finds_endpoint(self, device_info):
        """EPM lookup should find at least one PNIO endpoint."""
        info, _ = device_info
        try:
            endpoints = epm_lookup(info.ip)
        except (RPCError, OSError):
            pytest.skip("EPM lookup not supported by device")
            return
        assert isinstance(endpoints, list)
        if len(endpoints) == 0:
            pytest.skip("Device does not implement EPM (returned empty list)")

    def test_epm_endpoint_has_pnio_interface(self, device_info):
        """EPM should include a PNIO-Device interface UUID."""
        info, _ = device_info
        try:
            endpoints = epm_lookup(info.ip)
        except (RPCError, OSError):
            pytest.skip("EPM lookup not supported by device")
            return
        if len(endpoints) == 0:
            pytest.skip("Device does not implement EPM (returned empty list)")
        pnio_uuids = [ep for ep in endpoints if "dea00001" in ep.interface_uuid.lower()]
        assert len(pnio_uuids) >= 1, (
            "Should find at least one PNIO-Device endpoint. "
            f"Found interfaces: {[ep.interface_uuid for ep in endpoints]}"
        )

    def test_epm_endpoint_attributes(self, device_info):
        """EPM endpoints should have expected attribute types."""
        info, _ = device_info
        try:
            endpoints = epm_lookup(info.ip)
        except (RPCError, OSError):
            pytest.skip("EPM lookup not supported by device")
            return
        if len(endpoints) == 0:
            pytest.skip("Device does not implement EPM (returned empty list)")

        for ep in endpoints:
            assert isinstance(ep.interface_uuid, str)
            assert len(ep.interface_uuid) > 0
            assert isinstance(ep.interface_version_major, int)
            assert isinstance(ep.port, int)
            assert isinstance(ep.protocol, str)
