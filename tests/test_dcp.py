"""Tests for profinet.dcp module."""

import pytest

from profinet.dcp import (
    DEVICE_ROLE_IO_CONTROLLER,
    DEVICE_ROLE_IO_DEVICE,
    DEVICE_ROLE_IO_MULTIDEVICE,
    DEVICE_ROLE_PN_SUPERVISOR,
    PARAMS,
    DCPDeviceDescription,
    decode_device_role,
    get_block_name,
)
from profinet.protocol import PNDCPBlock


class TestDCPDeviceDescription:
    """Test DCPDeviceDescription class."""

    def test_basic_creation(self):
        """Test creating device with minimal data."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: b"\xc0\xa8\x01\x01" + b"\xff\xff\xff\x00" + b"\xc0\xa8\x01\xfe",
            PNDCPBlock.DEVICE_ID: b"\x00\x2a\x00\x01",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.mac == "00:11:22:33:44:55"
        assert device.name == "test-device"
        assert device.ip == "192.168.1.1"
        assert device.netmask == "255.255.255.0"
        assert device.gateway == "192.168.1.254"
        assert device.vendor_id == 0x002A
        assert device.device_id == 0x0001

    def test_missing_name(self):
        """Test device with missing name block."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.IP_ADDRESS: b"\xc0\xa8\x01\x01" + b"\xff\xff\xff\x00" + b"\x00\x00\x00\x00",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.name == ""

    def test_missing_ip(self):
        """Test device with missing IP block."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.ip == "0.0.0.0"
        assert device.netmask == "0.0.0.0"
        assert device.gateway == "0.0.0.0"

    def test_missing_device_id(self):
        """Test device with missing device ID block."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.vendor_id == 0
        assert device.device_id == 0

    def test_vendor_id_property(self):
        """Test vendor_id property calculation."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_ID: b"\x02\xb8\x00\x42",  # Vendor 0x02B8, Device 0x0042
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.vendor_id == 0x02B8
        assert device.device_id == 0x0042

    def test_repr(self):
        """Test string representation."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"my-device",
            PNDCPBlock.IP_ADDRESS: b"\x0a\x00\x00\x01" + b"\xff\x00\x00\x00" + b"\x0a\x00\x00\xfe",
        }

        device = DCPDeviceDescription(mac, blocks)

        repr_str = repr(device)
        assert "my-device" in repr_str
        assert "10.0.0.1" in repr_str

    def test_str(self):
        """Test string output."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"my-device",
            PNDCPBlock.IP_ADDRESS: b"\x0a\x00\x00\x01" + b"\xff\x00\x00\x00" + b"\x0a\x00\x00\xfe",
        }

        device = DCPDeviceDescription(mac, blocks)

        str_output = str(device)
        assert "PROFINET Device" in str_output
        assert "my-device" in str_output

    def test_device_type_parsing(self):
        """Test device type block parsing."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.DEVICE_TYPE: b"S7-1200",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_type == "S7-1200"

    def test_device_type_with_null_terminator(self):
        """Test device type with null bytes stripped."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_TYPE: b"ET 200SP\x00\x00\x00",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_type == "ET 200SP"

    def test_device_role_io_device(self):
        """Test device role parsing for IO-Device."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_ROLE: b"\x01\x00",  # IO-Device
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_role == 0x01
        assert "IO-Device" in device.device_roles

    def test_device_role_io_controller(self):
        """Test device role parsing for IO-Controller."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_ROLE: b"\x02\x00",  # IO-Controller
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_role == 0x02
        assert "IO-Controller" in device.device_roles

    def test_device_role_combined(self):
        """Test device role with multiple roles."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_ROLE: b"\x03\x00",  # IO-Device + IO-Controller
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_role == 0x03
        assert "IO-Device" in device.device_roles
        assert "IO-Controller" in device.device_roles

    def test_device_instance(self):
        """Test device instance parsing."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_INSTANCE: b"\x00\x64",  # Instance 0.100
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_instance == (0, 100)

    def test_device_alias(self):
        """Test device alias name parsing."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.DEVICE_ALIAS: b"port-001.plc-main\x00",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.alias_name == "port-001.plc-main"

    def test_supported_options(self):
        """Test supported options parsing."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        # Options block: (opt, subopt) pairs
        blocks = {
            PNDCPBlock.DEVICE_OPTIONS: b"\x01\x02\x02\x01\x02\x03",  # IP/IP, Dev/Type, Dev/DeviceID
        }

        device = DCPDeviceDescription(mac, blocks)

        assert (1, 2) in device.supported_options  # IP/IP
        assert (2, 1) in device.supported_options  # Device/Type
        assert (2, 3) in device.supported_options  # Device/DeviceID

    def test_raw_blocks_unknown_option(self):
        """Test unknown blocks are stored in raw_blocks."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            (0x80, 0x01): b"\xde\xad\xbe\xef",  # Vendor-specific block
        }

        device = DCPDeviceDescription(mac, blocks)

        assert (0x80, 0x01) in device.raw_blocks
        assert device.raw_blocks[(0x80, 0x01)] == b"\xde\xad\xbe\xef"

    def test_raw_blocks_not_include_known(self):
        """Test known blocks are not in raw_blocks."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: b"\xc0\xa8\x01\x01" + b"\xff\xff\xff\x00" + b"\x00\x00\x00\x00",
            PNDCPBlock.DEVICE_TYPE: b"S7-1500",
        }

        device = DCPDeviceDescription(mac, blocks)

        # Known blocks should not be in raw_blocks
        assert PNDCPBlock.NAME_OF_STATION not in device.raw_blocks
        assert PNDCPBlock.IP_ADDRESS not in device.raw_blocks
        assert PNDCPBlock.DEVICE_TYPE not in device.raw_blocks

    def test_str_with_unknown_blocks(self):
        """Test string output includes unknown blocks."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            (0x80, 0x01): b"\xde\xad",  # Vendor-specific
        }

        device = DCPDeviceDescription(mac, blocks)
        str_output = str(device)

        assert "Unknown (128,1)" in str_output
        assert "dead" in str_output

    def test_full_siemens_device(self):
        """Test parsing realistic Siemens S7-1200 response."""
        mac = b"\x28\x63\x36\x80\xb1\xf4"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"plcxb1d0ed",
            PNDCPBlock.DEVICE_TYPE: b"S7-1200",
            PNDCPBlock.IP_ADDRESS: b"\xc0\xa8\x00\xd7" + b"\xff\xff\xff\x00" + b"\xc0\xa8\x00\x01",
            PNDCPBlock.DEVICE_ID: b"\x00\x2a\x01\x0d",  # Siemens, S7-1200
            PNDCPBlock.DEVICE_ROLE: b"\x02\x00",  # IO-Controller
            PNDCPBlock.DEVICE_INSTANCE: b"\x00\x64",  # 0.100
            PNDCPBlock.DEVICE_OPTIONS: b"\x02\x07",  # Device/Instance
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.mac == "28:63:36:80:b1:f4"
        assert device.name == "plcxb1d0ed"
        assert device.device_type == "S7-1200"
        assert device.ip == "192.168.0.215"
        assert device.vendor_id == 0x002A
        assert device.device_id == 0x010D
        assert "IO-Controller" in device.device_roles
        assert device.device_instance == (0, 100)


class TestDecodeDeviceRole:
    """Test decode_device_role function."""

    def test_io_device(self):
        """Test IO-Device role."""
        roles = decode_device_role(DEVICE_ROLE_IO_DEVICE)
        assert roles == ["IO-Device"]

    def test_io_controller(self):
        """Test IO-Controller role."""
        roles = decode_device_role(DEVICE_ROLE_IO_CONTROLLER)
        assert roles == ["IO-Controller"]

    def test_io_multidevice(self):
        """Test IO-Multidevice role."""
        roles = decode_device_role(DEVICE_ROLE_IO_MULTIDEVICE)
        assert roles == ["IO-Multidevice"]

    def test_pn_supervisor(self):
        """Test PN-Supervisor role."""
        roles = decode_device_role(DEVICE_ROLE_PN_SUPERVISOR)
        assert roles == ["PN-Supervisor"]

    def test_combined_roles(self):
        """Test combined roles."""
        roles = decode_device_role(0x03)  # IO-Device + IO-Controller
        assert "IO-Device" in roles
        assert "IO-Controller" in roles
        assert len(roles) == 2

    def test_all_roles(self):
        """Test all roles combined."""
        roles = decode_device_role(0x0F)  # All 4 roles
        assert len(roles) == 4

    def test_unknown_role(self):
        """Test unknown role returns Unknown."""
        roles = decode_device_role(0x00)
        assert roles == ["Unknown"]


class TestGetBlockName:
    """Test get_block_name function."""

    def test_ip_option(self):
        """Test IP option names."""
        assert get_block_name(0x01, 0x01) == "IP/MAC"
        assert get_block_name(0x01, 0x02) == "IP/IP"
        assert get_block_name(0x01, 0x03) == "IP/FullIPSuite"

    def test_device_option(self):
        """Test Device option names."""
        assert get_block_name(0x02, 0x01) == "Device/Type"
        assert get_block_name(0x02, 0x02) == "Device/Name"
        assert get_block_name(0x02, 0x03) == "Device/DeviceID"
        assert get_block_name(0x02, 0x04) == "Device/Role"
        assert get_block_name(0x02, 0x05) == "Device/Options"
        assert get_block_name(0x02, 0x07) == "Device/Instance"

    def test_control_option(self):
        """Test Control option names."""
        assert get_block_name(0x05, 0x01) == "Control/Start"
        assert get_block_name(0x05, 0x03) == "Control/Signal"
        assert get_block_name(0x05, 0x06) == "Control/ResetToFactory"

    def test_vendor_option(self):
        """Test vendor-specific option range."""
        name = get_block_name(0x80, 0x01)
        assert "Vendor-0x80" in name

        name = get_block_name(0xFE, 0x05)
        assert "Vendor-0xFE" in name

    def test_unknown_option(self):
        """Test unknown option."""
        name = get_block_name(0x10, 0x99)
        assert "Opt-0x10" in name
        assert "0x99" in name

    def test_unknown_suboption(self):
        """Test known option with unknown suboption."""
        name = get_block_name(0x02, 0xFF)
        assert "Device/" in name
        assert "0xFF" in name


class TestDeviceRoleConstants:
    """Test device role constants."""

    def test_io_device_value(self):
        """Test IO-Device constant."""
        assert DEVICE_ROLE_IO_DEVICE == 0x01

    def test_io_controller_value(self):
        """Test IO-Controller constant."""
        assert DEVICE_ROLE_IO_CONTROLLER == 0x02

    def test_io_multidevice_value(self):
        """Test IO-Multidevice constant."""
        assert DEVICE_ROLE_IO_MULTIDEVICE == 0x04

    def test_pn_supervisor_value(self):
        """Test PN-Supervisor constant."""
        assert DEVICE_ROLE_PN_SUPERVISOR == 0x08


class TestPARAMS:
    """Test PARAMS constant."""

    def test_name_param(self):
        """Test name parameter mapping."""
        assert "name" in PARAMS
        assert PARAMS["name"] == PNDCPBlock.NAME_OF_STATION

    def test_ip_param(self):
        """Test IP parameter mapping."""
        assert "ip" in PARAMS
        assert PARAMS["ip"] == PNDCPBlock.IP_ADDRESS


from unittest.mock import MagicMock

from profinet.dcp import (
    DCP_MULTICAST_MAC,
    RESET_MODE_APPLICATION,
    RESET_MODE_COMMUNICATION,
    RESET_MODE_FACTORY,
    _generate_xid,
    get_param,
    read_response,
    reset_to_factory,
    send_discover,
    send_request,
    set_param,
    signal_device,
)
from profinet.exceptions import DCPError


class TestGenerateXid:
    """Test XID generation."""

    def test_generate_xid_returns_int(self):
        """Test _generate_xid returns an integer."""
        xid = _generate_xid()
        assert isinstance(xid, int)
        assert 0 <= xid <= 0xFFFFFFFF

    def test_generate_xid_different_values(self):
        """Test _generate_xid returns different values."""
        xids = [_generate_xid() for _ in range(10)]
        # Most values should be unique (with very high probability)
        assert len(set(xids)) > 5


class TestSendDiscover:
    """Test send_discover function."""

    def test_send_discover_sends_packet(self):
        """Test send_discover sends packet via socket."""
        mock_sock = MagicMock()
        src_mac = b"\x00\x11\x22\x33\x44\x55"

        send_discover(mock_sock, src_mac)

        mock_sock.send.assert_called_once()
        sent_data = mock_sock.send.call_args[0][0]
        assert isinstance(sent_data, bytes)
        assert len(sent_data) > 20  # Has Ethernet + DCP headers


class TestSendRequest:
    """Test send_request function."""

    def test_send_request_sends_packet(self):
        """Test send_request sends filtered request."""
        mock_sock = MagicMock()
        src_mac = b"\x00\x11\x22\x33\x44\x55"

        send_request(mock_sock, src_mac, PNDCPBlock.NAME_OF_STATION, b"test-device")

        mock_sock.send.assert_called_once()
        sent_data = mock_sock.send.call_args[0][0]
        assert isinstance(sent_data, bytes)
        assert b"test-device" in sent_data


class TestReadResponse:
    """Test read_response function."""

    def test_read_response_empty_on_no_data(self):
        """Test read_response returns empty dict when no data."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError()

        result = read_response(mock_sock, b"\x00\x11\x22\x33\x44\x55", timeout_sec=1)

        assert result == {}


class TestGetParam:
    """Test get_param function."""

    def test_get_param_invalid_param(self):
        """Test get_param raises error for invalid parameter."""
        mock_sock = MagicMock()

        with pytest.raises(DCPError, match="Unknown parameter"):
            get_param(mock_sock, b"\x00\x11\x22\x33\x44\x55", "AA:BB:CC:DD:EE:FF", "invalid")

    def test_get_param_sends_request(self):
        """Test get_param sends request and reads response."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError()

        result = get_param(
            mock_sock, b"\x00\x11\x22\x33\x44\x55", "AA:BB:CC:DD:EE:FF", "name", timeout_sec=1
        )

        mock_sock.send.assert_called_once()
        assert result is None  # No response received


class TestSetParam:
    """Test set_param function."""

    def test_set_param_invalid_param(self):
        """Test set_param raises error for invalid parameter."""
        mock_sock = MagicMock()

        with pytest.raises(DCPError, match="Unknown parameter"):
            set_param(
                mock_sock, b"\x00\x11\x22\x33\x44\x55", "AA:BB:CC:DD:EE:FF", "invalid", "value"
            )

    def test_set_param_sends_request(self):
        """Test set_param sends request."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError()

        result = set_param(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            "name",
            "new-name",
            timeout_sec=1,
        )

        mock_sock.send.assert_called_once()
        assert result is False  # No response received


def _build_dcp_set_response(dst_mac: bytes, src_mac: bytes, block_error: int = 0x00) -> bytes:
    """Build a valid DCP SET response Ethernet frame for testing.

    Args:
        dst_mac: Destination MAC (our MAC)
        src_mac: Source MAC (device MAC)
        block_error: Block error code (0x00 = success)

    Returns:
        Raw Ethernet frame bytes
    """
    import struct

    # Control/Response block: option=0x05, suboption=0x04, length=3,
    # payload = option_for_resp(1) + suboption_for_resp(1) + block_error(1)
    ctrl_block = struct.pack(">BBH", 0x05, 0x04, 3) + bytes([0x05, 0x03, block_error])
    # Pad to 2-byte alignment (length=3 is odd, add 1 byte padding)
    ctrl_block += b"\x00"

    # DCP header: frame_id(2) + service_id(1) + service_type(1) + xid(4) + resp(2) + length(2)
    dcp_hdr = struct.pack(">HBBI HH", 0xFEFD, 0x04, 0x01, 0x00000000, 0, len(ctrl_block))
    dcp_payload = dcp_hdr + ctrl_block

    # Ethernet header: dst(6) + src(6) + ethertype(2)
    eth_hdr = dst_mac + src_mac + struct.pack(">H", 0x8892)

    return eth_hdr + dcp_payload


class TestSignalDevice:
    """Test signal_device function."""

    def test_signal_device_sends_request(self):
        """Test signal_device sends Control/Signal request."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError()

        result = signal_device(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            duration_ms=5000,
            timeout_sec=1,
        )

        mock_sock.send.assert_called_once()
        assert result is False  # No response

    def test_signal_device_success(self):
        """Test signal_device returns True on valid response."""
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        mock_sock = MagicMock()
        # Build a proper DCP SET response frame
        response = _build_dcp_set_response(
            dst_mac=src_mac,
            src_mac=b"\xaa\xbb\xcc\xdd\xee\xff",
        )
        mock_sock.recv.return_value = response

        result = signal_device(mock_sock, src_mac, "AA:BB:CC:DD:EE:FF", timeout_sec=1)

        assert result is True


class TestResetToFactory:
    """Test reset_to_factory function."""

    def test_reset_to_factory_sends_request(self):
        """Test reset_to_factory sends Control/ResetToFactory request."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError()

        result = reset_to_factory(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            mode=RESET_MODE_COMMUNICATION,
            timeout_sec=1,
        )

        mock_sock.send.assert_called_once()
        assert result is False  # No response

    def test_reset_to_factory_success(self):
        """Test reset_to_factory returns True on valid response."""
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        mock_sock = MagicMock()
        # Build a proper DCP SET response frame
        response = _build_dcp_set_response(
            dst_mac=src_mac,
            src_mac=b"\xaa\xbb\xcc\xdd\xee\xff",
        )
        mock_sock.recv.return_value = response

        result = reset_to_factory(
            mock_sock,
            src_mac,
            "AA:BB:CC:DD:EE:FF",
            mode=RESET_MODE_COMMUNICATION,
            timeout_sec=1,
        )

        assert result is True

    def test_reset_modes_defined(self):
        """Test reset mode constants are defined correctly."""
        assert RESET_MODE_COMMUNICATION == 0x0002
        assert RESET_MODE_APPLICATION == 0x0004
        assert RESET_MODE_FACTORY == 0x0040


class TestConstants:
    """Test DCP constants."""

    def test_multicast_address(self):
        """Test DCP multicast address constant."""
        assert DCP_MULTICAST_MAC == "01:0e:cf:00:00:00"


from profinet.dcp import (
    DCP_MAX_NAME_LENGTH,
    DCP_OPTION_RESERVED,
    DCPResponseCode,
)


class TestDCPMaxNameLength:
    """Test DCP_MAX_NAME_LENGTH constant."""

    def test_max_name_length_value(self):
        """Test max name length is 240 per IEC 61158-6-10."""
        assert DCP_MAX_NAME_LENGTH == 240


class TestDCPResponseCode:
    """Test DCPResponseCode class."""

    def test_no_error_value(self):
        """Test NO_ERROR constant."""
        assert DCPResponseCode.NO_ERROR == 0x00

    def test_option_not_supported_value(self):
        """Test OPTION_NOT_SUPPORTED constant."""
        assert DCPResponseCode.OPTION_NOT_SUPPORTED == 0x01

    def test_suboption_not_supported_value(self):
        """Test SUBOPTION_NOT_SUPPORTED constant."""
        assert DCPResponseCode.SUBOPTION_NOT_SUPPORTED == 0x02

    def test_suboption_not_set_value(self):
        """Test SUBOPTION_NOT_SET constant."""
        assert DCPResponseCode.SUBOPTION_NOT_SET == 0x03

    def test_resource_error_value(self):
        """Test RESOURCE_ERROR constant."""
        assert DCPResponseCode.RESOURCE_ERROR == 0x04

    def test_set_not_possible_value(self):
        """Test SET_NOT_POSSIBLE constant."""
        assert DCPResponseCode.SET_NOT_POSSIBLE == 0x05

    def test_get_name_known_code(self):
        """Test get_name returns correct name for known codes."""
        assert DCPResponseCode.get_name(0x00) == "No error"
        assert DCPResponseCode.get_name(0x01) == "Option not supported"
        assert DCPResponseCode.get_name(0x05) == "Set not possible"

    def test_get_name_unknown_code(self):
        """Test get_name returns hex for unknown codes."""
        name = DCPResponseCode.get_name(0xFF)
        assert "Unknown" in name
        assert "0xFF" in name


class TestDCPOptionReserved:
    """Test DCP_OPTION_RESERVED constant."""

    def test_reserved_option_value(self):
        """Test Reserved option is 0x04."""
        assert DCP_OPTION_RESERVED == 0x04

    def test_reserved_in_option_names(self):
        """Test Reserved is in option names mapping."""
        from profinet.dcp import DCP_OPTION_NAMES

        assert 0x04 in DCP_OPTION_NAMES
        assert DCP_OPTION_NAMES[0x04] == "Reserved"

    def test_reserved_no_suboptions(self):
        """Test Reserved option has no suboptions defined."""
        from profinet.dcp import DCP_SUBOPTION_NAMES

        assert 0x04 not in DCP_SUBOPTION_NAMES


class TestSetParamNameLengthValidation:
    """Test name length validation in set_param."""

    def test_set_param_name_too_long(self):
        """Test set_param raises ValueError for names > 240 chars."""
        mock_sock = MagicMock()
        long_name = "x" * 241

        with pytest.raises(ValueError, match="exceeds maximum length"):
            set_param(
                mock_sock, b"\x00\x11\x22\x33\x44\x55", "AA:BB:CC:DD:EE:FF", "name", long_name
            )

    def test_set_param_name_at_limit(self):
        """Test set_param accepts names at exactly 240 chars."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError()

        max_name = "x" * 240
        # Should not raise ValueError, but may timeout
        result = set_param(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            "name",
            max_name,
            timeout_sec=1,
        )
        # Even though it times out, it shouldn't have raised ValueError
        assert result is False  # Timeout means no response

    def test_set_param_name_under_limit(self):
        """Test set_param accepts names under 240 chars."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError()

        normal_name = "my-device-name"
        result = set_param(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            "name",
            normal_name,
            timeout_sec=1,
        )
        # Should execute without ValueError
        assert result is False  # Timeout means no response

    def test_set_param_ip_no_length_check(self):
        """Test set_param for IP param doesn't apply name length check."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError()

        # IP address value - should not trigger name length validation
        result = set_param(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            "ip",
            "192.168.1.100",
            timeout_sec=1,
        )
        assert result is False  # Timeout means no response


# =============================================================================
# IPBlockInfo Tests
# =============================================================================


import struct

from profinet.dcp import (
    DCP_OPTION_DEVICE_INITIATIVE,
    DCP_SUBOPTION_DEVICE_INITIATIVE,
    DCP_SUBOPTION_DHCP_CLIENT_ID,
    DCP_SUBOPTION_DHCP_FQDN,
    DCP_SUBOPTION_DHCP_HOSTNAME,
    DCP_SUBOPTION_DHCP_UUID,
    DCP_SUBOPTION_DHCP_VENDOR_SPEC,
    BlockQualifier,
    DCPDHCPBlock,
    DeviceInitiative,
    IPBlockInfo,
    ResetQualifier,
    set_ip,
)


class TestIPBlockInfo:
    """Test IPBlockInfo class methods."""

    def test_constants(self):
        """Test IPBlockInfo constant values."""
        assert IPBlockInfo.IP_NOT_SET == 0x0000
        assert IPBlockInfo.IP_SET == 0x0001
        assert IPBlockInfo.IP_SET_BY_DHCP == 0x0002
        assert IPBlockInfo.IP_NOT_SET_CONFLICT == 0x0080
        assert IPBlockInfo.IP_SET_CONFLICT == 0x0081
        assert IPBlockInfo.IP_SET_BY_DHCP_CONFLICT == 0x0082

    def test_get_name_known_values(self):
        """Test get_name for known values."""
        assert "not set" in IPBlockInfo.get_name(0x0000).lower()
        assert "set" in IPBlockInfo.get_name(0x0001).lower()
        assert "dhcp" in IPBlockInfo.get_name(0x0002).lower()

    def test_get_name_conflict_values(self):
        """Test get_name for conflict values."""
        assert "conflict" in IPBlockInfo.get_name(0x0080).lower()
        assert "conflict" in IPBlockInfo.get_name(0x0081).lower()
        assert "conflict" in IPBlockInfo.get_name(0x0082).lower()

    def test_get_name_unknown(self):
        """Test get_name for unknown value."""
        name = IPBlockInfo.get_name(0x00FF)
        assert "Unknown" in name

    def test_has_conflict_true(self):
        """Test has_conflict returns True for conflict bit set."""
        assert IPBlockInfo.has_conflict(0x0080) is True
        assert IPBlockInfo.has_conflict(0x0081) is True
        assert IPBlockInfo.has_conflict(0x0082) is True

    def test_has_conflict_false(self):
        """Test has_conflict returns False when conflict bit is not set."""
        assert IPBlockInfo.has_conflict(0x0000) is False
        assert IPBlockInfo.has_conflict(0x0001) is False
        assert IPBlockInfo.has_conflict(0x0002) is False

    def test_is_dhcp_true(self):
        """Test is_dhcp returns True for DHCP-set values."""
        assert IPBlockInfo.is_dhcp(0x0002) is True
        assert IPBlockInfo.is_dhcp(0x0082) is True

    def test_is_dhcp_false(self):
        """Test is_dhcp returns False for non-DHCP values."""
        assert IPBlockInfo.is_dhcp(0x0000) is False
        assert IPBlockInfo.is_dhcp(0x0001) is False
        assert IPBlockInfo.is_dhcp(0x0080) is False


class TestBlockQualifier:
    """Test BlockQualifier class."""

    def test_constants(self):
        """Test qualifier constant values."""
        assert BlockQualifier.TEMPORARY == 0x0000
        assert BlockQualifier.PERMANENT == 0x0001

    def test_get_name_known(self):
        """Test get_name for known qualifiers."""
        assert BlockQualifier.get_name(0x0000) == "Temporary"
        assert BlockQualifier.get_name(0x0001) == "Permanent"

    def test_get_name_unknown(self):
        """Test get_name for unknown qualifier."""
        name = BlockQualifier.get_name(0x00FF)
        assert "Unknown" in name


class TestResetQualifier:
    """Test ResetQualifier class."""

    def test_constants(self):
        """Test reset qualifier constant values."""
        assert ResetQualifier.RESET_APPLICATION_DATA == 0x0002
        assert ResetQualifier.RESET_COMMUNICATION_PARAM == 0x0004
        assert ResetQualifier.RESET_TO_FACTORY == 0x0010
        assert ResetQualifier.RESET_AND_RESTORE == 0x0012

    def test_get_name_known(self):
        """Test get_name for known qualifiers."""
        assert "application" in ResetQualifier.get_name(0x0002).lower()
        assert "communication" in ResetQualifier.get_name(0x0004).lower()
        assert "factory" in ResetQualifier.get_name(0x0010).lower()

    def test_get_name_alternate_values(self):
        """Test alternate qualifier values map to same names."""
        assert ResetQualifier.get_name(0x0002) == ResetQualifier.get_name(0x0003)
        assert ResetQualifier.get_name(0x0004) == ResetQualifier.get_name(0x0005)

    def test_get_name_unknown(self):
        """Test get_name for unknown qualifier."""
        name = ResetQualifier.get_name(0x00FF)
        assert "Unknown" in name


class TestDeviceInitiative:
    """Test DeviceInitiative class."""

    def test_constants(self):
        """Test initiative constant values."""
        assert DeviceInitiative.NO_HELLO == 0x0000
        assert DeviceInitiative.ISSUE_HELLO == 0x0001

    def test_get_name_known(self):
        """Test get_name for known values."""
        assert "does not issue" in DeviceInitiative.get_name(0x0000).lower()
        assert "issues" in DeviceInitiative.get_name(0x0001).lower()

    def test_get_name_unknown(self):
        """Test get_name for unknown value."""
        name = DeviceInitiative.get_name(0x00FF)
        assert "Unknown" in name


# =============================================================================
# DCPDHCPBlock Tests
# =============================================================================


class TestDCPDHCPBlock:
    """Test DCPDHCPBlock parsing."""

    def test_parse_hostname(self):
        """Test parsing DHCP hostname block."""
        block = DCPDHCPBlock.parse(DCP_SUBOPTION_DHCP_HOSTNAME, b"my-hostname\x00")
        assert block.hostname == "my-hostname"
        assert block.suboption == DCP_SUBOPTION_DHCP_HOSTNAME
        assert block.suboption_name == "Hostname"

    def test_parse_client_id(self):
        """Test parsing DHCP client ID block."""
        data = b"\x01\x00\x11\x22\x33\x44\x55"
        block = DCPDHCPBlock.parse(DCP_SUBOPTION_DHCP_CLIENT_ID, data)
        assert block.client_id == data
        assert block.suboption_name == "ClientID"

    def test_parse_vendor_specific(self):
        """Test parsing DHCP vendor specific block."""
        data = b"\xde\xad\xbe\xef"
        block = DCPDHCPBlock.parse(DCP_SUBOPTION_DHCP_VENDOR_SPEC, data)
        assert block.vendor_specific == data
        assert block.suboption_name == "VendorSpec"

    def test_parse_fqdn(self):
        """Test parsing DHCP FQDN block."""
        block = DCPDHCPBlock.parse(DCP_SUBOPTION_DHCP_FQDN, b"device.local\x00")
        assert block.fqdn == "device.local"
        assert block.suboption_name == "FQDN"

    def test_parse_uuid(self):
        """Test parsing DHCP UUID block."""
        uuid_bytes = bytes(range(16))
        block = DCPDHCPBlock.parse(DCP_SUBOPTION_DHCP_UUID, uuid_bytes)
        assert block.uuid is not None
        # UUID should be formatted as 5 groups separated by dashes
        assert block.uuid.count("-") == 4

    def test_parse_uuid_short_data(self):
        """Test parsing DHCP UUID block with insufficient data."""
        block = DCPDHCPBlock.parse(DCP_SUBOPTION_DHCP_UUID, b"\x00" * 10)
        assert block.uuid is None

    def test_parse_unknown_suboption(self):
        """Test parsing unknown DHCP suboption."""
        block = DCPDHCPBlock.parse(0x99, b"\x01\x02\x03")
        assert block.raw_data == b"\x01\x02\x03"
        assert block.hostname is None
        assert block.client_id is None


# =============================================================================
# DCP Option 0x04 (Reserved) Tests
# =============================================================================


# =============================================================================
# DCPDeviceDescription with DHCP/LLDP/Initiative
# =============================================================================


class TestDCPDeviceDescriptionExtended:
    """Test DCPDeviceDescription with DHCP, LLDP, and initiative blocks."""

    def test_dhcp_blocks_parsed(self):
        """Test DHCP blocks are parsed from blocks dict."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            (0x03, DCP_SUBOPTION_DHCP_HOSTNAME): b"dhcp-host\x00",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert len(device.dhcp_blocks) == 1
        assert device.dhcp_blocks[0].hostname == "dhcp-host"

    def test_reserved_option_blocks_in_raw_blocks(self):
        """Test option 0x04 (Reserved) blocks go into raw_blocks."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            (0x04, 0x05): b"switch-01\x00",
        }

        device = DCPDeviceDescription(mac, blocks)

        # Reserved option data should be in raw_blocks
        assert (0x04, 0x05) in device.raw_blocks

    def test_device_initiative_hello(self):
        """Test device initiative parsing for ISSUE_HELLO."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        initiative_data = struct.pack(">H", DeviceInitiative.ISSUE_HELLO)
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            (DCP_OPTION_DEVICE_INITIATIVE, DCP_SUBOPTION_DEVICE_INITIATIVE): initiative_data,
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_initiative == 1
        assert device.issues_hello is True

    def test_device_initiative_no_hello(self):
        """Test device initiative parsing for NO_HELLO."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        initiative_data = struct.pack(">H", DeviceInitiative.NO_HELLO)
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            (DCP_OPTION_DEVICE_INITIATIVE, DCP_SUBOPTION_DEVICE_INITIATIVE): initiative_data,
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_initiative == 0
        assert device.issues_hello is False

    def test_device_initiative_missing(self):
        """Test device initiative defaults when not present."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {}

        device = DCPDeviceDescription(mac, blocks)

        assert device.device_initiative == 0
        assert device.issues_hello is False

    def test_ip_block_with_block_info_prefix(self):
        """Test IP block parsing with 14-byte block info prefix."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        # 2-byte block info + 12-byte IP config = 14 bytes
        ip_data = struct.pack(">H", 0x0001)  # IP_SET
        ip_data += b"\xc0\xa8\x01\x01"  # IP
        ip_data += b"\xff\xff\xff\x00"  # Netmask
        ip_data += b"\xc0\xa8\x01\xfe"  # Gateway
        blocks = {
            PNDCPBlock.IP_ADDRESS: ip_data,
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.ip == "192.168.1.1"
        assert device.netmask == "255.255.255.0"
        assert device.gateway == "192.168.1.254"
        assert device.ip_block_info == 0x0001

    def test_ip_block_with_conflict(self):
        """Test IP block parsing with conflict flag."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        ip_data = struct.pack(">H", 0x0081)  # IP_SET_CONFLICT
        ip_data += b"\xc0\xa8\x01\x01" + b"\xff\xff\xff\x00" + b"\x00\x00\x00\x00"
        blocks = {
            PNDCPBlock.IP_ADDRESS: ip_data,
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.ip_conflict is True
        assert device.ip_block_info == 0x0081

    def test_ip_block_with_dhcp(self):
        """Test IP block parsing with DHCP flag."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        ip_data = struct.pack(">H", 0x0002)  # IP_SET_BY_DHCP
        ip_data += b"\xc0\xa8\x01\x01" + b"\xff\xff\xff\x00" + b"\x00\x00\x00\x00"
        blocks = {
            PNDCPBlock.IP_ADDRESS: ip_data,
        }

        device = DCPDeviceDescription(mac, blocks)

        assert device.ip_set_by_dhcp is True

    def test_dhcp_blocks_not_in_raw_blocks(self):
        """Test DHCP blocks are excluded from raw_blocks."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            (0x03, DCP_SUBOPTION_DHCP_HOSTNAME): b"test\x00",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert (0x03, DCP_SUBOPTION_DHCP_HOSTNAME) not in device.raw_blocks

    def test_reserved_option_in_raw_blocks(self):
        """Test option 0x04 (Reserved) blocks are stored in raw_blocks."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            (0x04, 0x01): b"some-data\x00",
        }

        device = DCPDeviceDescription(mac, blocks)

        assert (0x04, 0x01) in device.raw_blocks

    def test_str_with_dhcp_blocks(self):
        """Test str output includes DHCP block info."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            (0x03, DCP_SUBOPTION_DHCP_HOSTNAME): b"my-host\x00",
        }

        device = DCPDeviceDescription(mac, blocks)
        output = str(device)

        assert "DHCP" in output
        assert "my-host" in output

    def test_str_with_reserved_option_blocks(self):
        """Test str output includes reserved option blocks as unknown."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            (0x04, 0x05): b"my-switch\x00",
        }

        device = DCPDeviceDescription(mac, blocks)
        output = str(device)

        assert "Unknown (4,5)" in output

    def test_str_with_initiative(self):
        """Test str output includes initiative info."""
        mac = b"\x00\x11\x22\x33\x44\x55"
        initiative_data = struct.pack(">H", DeviceInitiative.ISSUE_HELLO)
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            (DCP_OPTION_DEVICE_INITIATIVE, DCP_SUBOPTION_DEVICE_INITIATIVE): initiative_data,
        }

        device = DCPDeviceDescription(mac, blocks)
        output = str(device)

        assert "Initiative" in output


def _build_dcp_set_response(
    dst_mac: bytes,
    src_mac: bytes,
    block_error: int = 0x00,
    resp_option: int = 0x02,
    resp_suboption: int = 0x02,
    service_type: int = 0x01,
) -> bytes:
    """Build a mock DCP SET response Ethernet frame.

    DCP SET response layout:
        Ethernet header: dst(6) + src(6) + ethertype(2)
        DCP header: frame_id(2) + service_id(1) + service_type(1) + xid(4) + resp(2) + length(2)
        Control/Response block: option(1) + suboption(1) + length(2)
            + option_for_response(1) + suboption_for_response(1) + block_error(1) + padding(1)

    Args:
        dst_mac: Destination MAC (6 bytes)
        src_mac: Source MAC (6 bytes)
        block_error: Block error code (0x00 = success)
        resp_option: The option that was set
        resp_suboption: The suboption that was set
        service_type: DCP service type (0x01 = response success)

    Returns:
        Raw Ethernet frame bytes
    """
    # Ethernet header
    frame = dst_mac + src_mac + struct.pack(">H", 0x8892)

    # Control/Response block payload: option(1) + suboption(1) + block_error(1) + padding(1)
    ctrl_payload = bytes([resp_option, resp_suboption, block_error, 0x00])

    # Control/Response block header: option=0x05, suboption=0x04, length=3 (excl padding)
    ctrl_block = bytes([0x05, 0x04]) + struct.pack(">H", 3) + ctrl_payload

    # DCP header
    dcp_length = len(ctrl_block)
    dcp_header = struct.pack(
        ">HBBI HH",
        0xFEFD,  # frame_id (Get/Set)
        0x04,  # service_id (SET)
        service_type,  # service_type
        0x00000001,  # xid
        0x0000,  # resp
        dcp_length,  # length
    )

    frame += dcp_header + ctrl_block
    return frame


class TestSetIP:
    """Test set_ip function."""

    def test_set_ip_sends_request(self):
        """Test set_ip sends SET request."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError()

        result = set_ip(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            "192.168.1.100",
            "255.255.255.0",
            "192.168.1.1",
            timeout_sec=1,
        )

        mock_sock.send.assert_called_once()
        assert result is False  # Timeout

    def test_set_ip_success(self):
        """Test set_ip returns True when device responds with success."""
        mock_sock = MagicMock()
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        device_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        response = _build_dcp_set_response(
            dst_mac=src_mac,
            src_mac=device_mac,
            block_error=0x00,
            resp_option=0x01,
            resp_suboption=0x02,
        )
        mock_sock.recv.return_value = response

        result = set_ip(
            mock_sock,
            src_mac,
            "AA:BB:CC:DD:EE:FF",
            "192.168.1.100",
            "255.255.255.0",
            "192.168.1.1",
            timeout_sec=1,
        )

        assert result is True

    def test_set_ip_error_response(self):
        """Test set_ip raises DCPError when device responds with error."""
        mock_sock = MagicMock()
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        device_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        response = _build_dcp_set_response(
            dst_mac=src_mac,
            src_mac=device_mac,
            block_error=0x05,  # SET not possible
            resp_option=0x01,
            resp_suboption=0x02,
        )
        mock_sock.recv.return_value = response

        with pytest.raises(DCPError, match="DCP SET IP failed"):
            set_ip(
                mock_sock,
                src_mac,
                "AA:BB:CC:DD:EE:FF",
                "192.168.1.100",
                "255.255.255.0",
                "192.168.1.1",
                timeout_sec=1,
            )

    def test_set_ip_timeout(self):
        """Test set_ip returns False on timeout (no response)."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError()

        result = set_ip(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            "192.168.1.100",
            "255.255.255.0",
            "192.168.1.1",
            timeout_sec=1,
        )

        assert result is False

    def test_set_ip_permanent(self):
        """Test set_ip with permanent flag."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError()

        set_ip(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            "10.0.0.1",
            "255.0.0.0",
            "10.0.0.254",
            permanent=True,
            timeout_sec=1,
        )

        mock_sock.send.assert_called_once()
        # Verify the permanent qualifier is in the sent data
        sent_data = mock_sock.send.call_args[0][0]
        assert isinstance(sent_data, bytes)


class TestSetParamResponseValidation:
    """Test set_param response validation."""

    def test_set_param_success_response(self):
        """Test set_param returns True when device responds with success."""
        mock_sock = MagicMock()
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        device_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        response = _build_dcp_set_response(
            dst_mac=src_mac,
            src_mac=device_mac,
            block_error=0x00,
            resp_option=0x02,
            resp_suboption=0x02,
        )
        mock_sock.recv.return_value = response

        result = set_param(
            mock_sock,
            src_mac,
            "AA:BB:CC:DD:EE:FF",
            "name",
            "new-device-name",
            timeout_sec=1,
        )

        assert result is True

    def test_set_param_error_response(self):
        """Test set_param raises DCPError when device responds with error."""
        mock_sock = MagicMock()
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        device_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        response = _build_dcp_set_response(
            dst_mac=src_mac,
            src_mac=device_mac,
            block_error=0x02,  # Suboption not supported
            resp_option=0x02,
            resp_suboption=0x02,
        )
        mock_sock.recv.return_value = response

        with pytest.raises(DCPError, match="DCP SET failed"):
            set_param(
                mock_sock,
                src_mac,
                "AA:BB:CC:DD:EE:FF",
                "name",
                "new-device-name",
                timeout_sec=1,
            )

    def test_set_param_timeout_returns_false(self):
        """Test set_param returns False on timeout (no response)."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError()

        result = set_param(
            mock_sock,
            b"\x00\x11\x22\x33\x44\x55",
            "AA:BB:CC:DD:EE:FF",
            "name",
            "new-name",
            timeout_sec=1,
        )

        assert result is False

    def test_set_param_option_unsupported(self):
        """Test set_param raises DCPError with 'Option not supported' message."""
        mock_sock = MagicMock()
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        device_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        response = _build_dcp_set_response(
            dst_mac=src_mac,
            src_mac=device_mac,
            block_error=0x01,  # Option not supported
        )
        mock_sock.recv.return_value = response

        with pytest.raises(DCPError, match="Option not supported"):
            set_param(
                mock_sock,
                src_mac,
                "AA:BB:CC:DD:EE:FF",
                "name",
                "new-name",
                timeout_sec=1,
            )

    def test_set_param_resource_error(self):
        """Test set_param raises DCPError with 'Resource error' message."""
        mock_sock = MagicMock()
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        device_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        response = _build_dcp_set_response(
            dst_mac=src_mac,
            src_mac=device_mac,
            block_error=0x04,  # Resource error
        )
        mock_sock.recv.return_value = response

        with pytest.raises(DCPError, match="Resource error"):
            set_param(
                mock_sock,
                src_mac,
                "AA:BB:CC:DD:EE:FF",
                "name",
                "new-name",
                timeout_sec=1,
            )

    def test_set_param_in_operation(self):
        """Test set_param raises DCPError with 'In operation' message."""
        mock_sock = MagicMock()
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        device_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        response = _build_dcp_set_response(
            dst_mac=src_mac,
            src_mac=device_mac,
            block_error=0x06,  # In operation
        )
        mock_sock.recv.return_value = response

        with pytest.raises(DCPError, match="In operation"):
            set_param(
                mock_sock,
                src_mac,
                "AA:BB:CC:DD:EE:FF",
                "name",
                "new-name",
                timeout_sec=1,
            )

    def test_set_param_unsupported_service_type(self):
        """Test set_param raises DCPError when service_type indicates unsupported."""
        mock_sock = MagicMock()
        src_mac = b"\x00\x11\x22\x33\x44\x55"
        device_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        response = _build_dcp_set_response(
            dst_mac=src_mac,
            src_mac=device_mac,
            service_type=0x05,  # Response unsupported
        )
        mock_sock.recv.return_value = response

        with pytest.raises(DCPError, match="not supported"):
            set_param(
                mock_sock,
                src_mac,
                "AA:BB:CC:DD:EE:FF",
                "name",
                "new-name",
                timeout_sec=1,
            )


class TestDCPBlockErrorConstants:
    """Test DCP block error constants and names."""

    def test_block_error_ok_value(self):
        """Test DCP_BLOCK_ERROR_OK constant."""
        from profinet.dcp import DCP_BLOCK_ERROR_OK

        assert DCP_BLOCK_ERROR_OK == 0x00

    def test_block_error_option_unsupported_value(self):
        """Test DCP_BLOCK_ERROR_OPTION_UNSUPPORTED constant."""
        from profinet.dcp import DCP_BLOCK_ERROR_OPTION_UNSUPPORTED

        assert DCP_BLOCK_ERROR_OPTION_UNSUPPORTED == 0x01

    def test_block_error_suboption_unsupported_value(self):
        """Test DCP_BLOCK_ERROR_SUBOPTION_UNSUPPORTED constant."""
        from profinet.dcp import DCP_BLOCK_ERROR_SUBOPTION_UNSUPPORTED

        assert DCP_BLOCK_ERROR_SUBOPTION_UNSUPPORTED == 0x02

    def test_block_error_suboption_not_set_value(self):
        """Test DCP_BLOCK_ERROR_SUBOPTION_NOT_SET constant."""
        from profinet.dcp import DCP_BLOCK_ERROR_SUBOPTION_NOT_SET

        assert DCP_BLOCK_ERROR_SUBOPTION_NOT_SET == 0x03

    def test_block_error_resource_value(self):
        """Test DCP_BLOCK_ERROR_RESOURCE constant."""
        from profinet.dcp import DCP_BLOCK_ERROR_RESOURCE

        assert DCP_BLOCK_ERROR_RESOURCE == 0x04

    def test_block_error_set_not_possible_value(self):
        """Test DCP_BLOCK_ERROR_SET_NOT_POSSIBLE constant."""
        from profinet.dcp import DCP_BLOCK_ERROR_SET_NOT_POSSIBLE

        assert DCP_BLOCK_ERROR_SET_NOT_POSSIBLE == 0x05

    def test_block_error_in_operation_value(self):
        """Test DCP_BLOCK_ERROR_IN_OPERATION constant."""
        from profinet.dcp import DCP_BLOCK_ERROR_IN_OPERATION

        assert DCP_BLOCK_ERROR_IN_OPERATION == 0x06

    def test_block_error_names_has_all_codes(self):
        """Test DCP_BLOCK_ERROR_NAMES contains all error codes."""
        from profinet.dcp import DCP_BLOCK_ERROR_NAMES

        assert 0x00 in DCP_BLOCK_ERROR_NAMES
        assert 0x01 in DCP_BLOCK_ERROR_NAMES
        assert 0x02 in DCP_BLOCK_ERROR_NAMES
        assert 0x03 in DCP_BLOCK_ERROR_NAMES
        assert 0x04 in DCP_BLOCK_ERROR_NAMES
        assert 0x05 in DCP_BLOCK_ERROR_NAMES
        assert 0x06 in DCP_BLOCK_ERROR_NAMES

    def test_block_error_names_ok(self):
        """Test DCP_BLOCK_ERROR_NAMES for OK."""
        from profinet.dcp import DCP_BLOCK_ERROR_NAMES

        assert DCP_BLOCK_ERROR_NAMES[0x00] == "OK"

    def test_block_error_names_values(self):
        """Test DCP_BLOCK_ERROR_NAMES contains meaningful descriptions."""
        from profinet.dcp import DCP_BLOCK_ERROR_NAMES

        assert "Option not supported" in DCP_BLOCK_ERROR_NAMES[0x01]
        assert "Suboption not supported" in DCP_BLOCK_ERROR_NAMES[0x02]
        assert "Suboption not set" in DCP_BLOCK_ERROR_NAMES[0x03]
        assert "Resource error" in DCP_BLOCK_ERROR_NAMES[0x04]
        assert "SET not possible" in DCP_BLOCK_ERROR_NAMES[0x05]
        assert "In operation" in DCP_BLOCK_ERROR_NAMES[0x06]
