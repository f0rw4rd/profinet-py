"""Tests for RPC module - data classes and parsing."""

import struct as _struct
import sys
import time as _time
from struct import pack
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, ".")

from profinet.dcp import DCPDeviceDescription
from profinet.protocol import PNDCPBlock
from profinet.rpc import (
    MAU_TYPES,
    ARInfo,
    DiagnosisEntry,
    InterfaceInfo,
    LinkData,
    LogEntry,
    PortInfo,
    PortStatistics,
    RPCCon,
    get_station_info,
)


class TestDataClasses:
    """Test RPC data classes."""

    def test_port_statistics_defaults(self):
        stats = PortStatistics()
        assert stats.ifInOctets == 0
        assert stats.ifOutOctets == 0
        assert stats.ifInDiscards == 0
        assert stats.ifOutDiscards == 0
        assert stats.ifInErrors == 0
        assert stats.ifOutErrors == 0

    def test_port_statistics_values(self):
        stats = PortStatistics(ifInOctets=1000, ifOutOctets=2000, ifInErrors=5)
        assert stats.ifInOctets == 1000
        assert stats.ifOutOctets == 2000
        assert stats.ifInErrors == 5

    def test_link_data_defaults(self):
        link = LinkData()
        assert link.link_state == "unknown"
        assert link.link_speed == 0
        assert link.mau_type == 0
        assert link.mau_type_name == "unknown"

    def test_link_data_values(self):
        link = LinkData(link_state="up", link_speed=100, mau_type=16, mau_type_name="100BASE-TX FD")
        assert link.link_state == "up"
        assert link.mau_type == 16

    def test_port_info_defaults(self):
        port = PortInfo()
        assert port.slot == 0
        assert port.subslot == 0
        assert port.port_id == ""
        assert port.peer_port_id == ""
        assert port.peer_chassis_id == ""
        assert port.peer_mac == ""

    def test_port_info_values(self):
        port = PortInfo(
            slot=1,
            subslot=0x8001,
            port_id="port-001",
            peer_port_id="port-002",
            peer_chassis_id="device2",
        )
        assert port.slot == 1
        assert port.subslot == 0x8001
        assert port.port_id == "port-001"

    def test_interface_info_defaults(self):
        info = InterfaceInfo()
        assert info.chassis_id == ""
        assert info.mac == ""
        assert info.ip == ""
        assert info.netmask == ""
        assert info.gateway == ""

    def test_interface_info_values(self):
        info = InterfaceInfo(
            chassis_id="plc-001",
            mac="aa:bb:cc:dd:ee:ff",
            ip="192.168.1.100",
            netmask="255.255.255.0",
            gateway="192.168.1.1",
        )
        assert info.chassis_id == "plc-001"
        assert info.ip == "192.168.1.100"

    def test_diagnosis_entry_defaults(self):
        diag = DiagnosisEntry()
        assert diag.channel == 0
        assert diag.error_type == 0
        assert diag.ext_error_type == 0
        assert diag.add_value == 0

    def test_ar_info_defaults(self):
        ar = ARInfo()
        assert ar.ar_uuid == ""
        assert ar.ar_type == 0
        assert ar.ar_properties == 0
        assert ar.session_key == 0

    def test_log_entry_defaults(self):
        log = LogEntry()
        assert log.timestamp == 0
        assert log.entry_detail == 0

    def test_log_entry_values(self):
        log = LogEntry(timestamp=1234567890, entry_detail=0x12345678)
        assert log.timestamp == 1234567890
        assert log.entry_detail == 0x12345678


class TestMAUTypes:
    """Test MAU type mapping."""

    def test_mau_types_contains_common_values(self):
        assert 0 in MAU_TYPES
        assert 16 in MAU_TYPES  # 100BASE-TX FD
        assert 30 in MAU_TYPES  # 1000BASE-T FD

    def test_mau_types_100base_tx(self):
        assert MAU_TYPES[16] == "100BASE-TX FD"
        assert MAU_TYPES[15] == "100BASE-TX HD"

    def test_mau_types_gigabit(self):
        assert MAU_TYPES[30] == "1000BASE-T FD"


class TestRPCConInit:
    """Test RPCCon initialization."""

    def test_rpccon_init(self):
        # Create mock device info
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 100, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
        }
        info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", blocks)

        with patch("profinet.rpc.socket"):
            rpc = RPCCon(info)
            assert rpc.info == info
            assert rpc.peer == ("192.168.1.100", 0x8894)
            assert len(rpc.ar_uuid) == 16
            rpc.close()

    def test_rpccon_context_manager(self):
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 100, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
        }
        info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", blocks)

        with patch("profinet.rpc.socket"):
            with RPCCon(info) as rpc:
                assert rpc.info == info


class TestTopologyParsing:
    """Test topology data parsing."""

    def test_parse_interface_data(self):
        """Test parsing PDInterfaceDataReal block."""
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 100, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
        }
        info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", blocks)

        # Build PDRealData with interface block
        # Block type 0x0240, chassis "test", MAC, IP
        chassis = b"test"
        mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        ip = bytes([192, 168, 1, 100])
        mask = bytes([255, 255, 255, 0])
        gw = bytes([192, 168, 1, 1])

        # Build block content
        content = bytes([len(chassis)]) + chassis + bytes([0])  # name + padding
        content += bytes([0, 0])  # padding
        content += mac + bytes([0, 0])  # MAC + padding
        content += ip + mask + gw

        block = pack(">HH", 0x0240, len(content) + 2) + bytes([0x01, 0x00]) + content

        with patch("profinet.rpc.socket"):
            rpc = RPCCon(info)

            # Mock the read method
            mock_iod = MagicMock()
            mock_iod.payload = block
            rpc.read = MagicMock(return_value=mock_iod)

            interface, ports = rpc.read_topology()

            assert interface.chassis_id == "test"
            rpc.close()


class TestRecordEnumeration:
    """Test record enumeration."""

    def test_enumerate_records_structure(self):
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 1, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x01, 0x00, 0x01]),
        }
        info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", blocks)

        with patch("profinet.rpc.socket"):
            rpc = RPCCon(info)

            # Mock read to return data for some indices
            def mock_read(api, slot, subslot, idx):
                mock = MagicMock()
                if idx in [0xAFF0, 0xF000]:
                    mock.payload = bytes([0] * 60)
                else:
                    mock.payload = b""
                return mock

            rpc.read = mock_read

            records = rpc.enumerate_records()
            assert isinstance(records, dict)
            rpc.close()


class TestIMReading:
    """Test I&M record reading methods."""

    @pytest.fixture
    def mock_rpc(self):
        """Create a mocked RPCCon instance."""
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 100, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
        }
        info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", blocks)
        with patch("profinet.rpc.socket"):
            rpc = RPCCon(info)
            yield rpc
            rpc.close()

    def _create_im0_payload(self):
        """Create valid I&M0 payload for testing."""
        # Block header (6 bytes): type=0x0020, length, version
        header = pack(">HH", 0x0020, 58) + bytes([0x01, 0x00])
        # I&M0 data: vendor, order, serial, hw_rev, sw_rev, etc.
        vendor_id = pack(">H", 0x002A)  # vendor ID
        order_id = b"ORDER-123456" + bytes(20 - 12)  # 20 bytes
        serial = b"SERIAL-001" + bytes(16 - 10)  # 16 bytes
        hw_rev = pack(">H", 1)  # hardware revision
        sw_rev = bytes([0x01, 0x02, 0x03, 0x00])  # V01.02.03
        revision_counter = pack(">H", 1)
        profile_id = pack(">H", 0xF600)
        profile_type = pack(">H", 0x0001)
        im_version = bytes([0x01, 0x00])  # version 1.0
        im_supported = pack(">H", 0x000E)  # supports IM0-3
        return (
            header
            + vendor_id
            + order_id
            + serial
            + hw_rev
            + sw_rev
            + revision_counter
            + profile_id
            + profile_type
            + im_version
            + im_supported
        )

    def _create_im1_payload(self):
        """Create valid I&M1 payload for testing."""
        header = pack(">HH", 0x0021, 58) + bytes([0x01, 0x00])
        tag_function = b"TAG-FUNCTION" + bytes(32 - 12)  # 32 bytes
        tag_location = b"TAG-LOCATION" + bytes(22 - 12)  # 22 bytes
        return header + tag_function + tag_location

    def _create_im2_payload(self):
        """Create valid I&M2 payload for testing."""
        header = pack(">HH", 0x0022, 22) + bytes([0x01, 0x00])
        install_date = b"2024-01-15 10:30" + bytes(16 - 16)  # 16 bytes
        return header + install_date

    def _create_im3_payload(self):
        """Create valid I&M3 payload for testing."""
        header = pack(">HH", 0x0023, 60) + bytes([0x01, 0x00])
        descriptor = b"Device Descriptor Text" + bytes(54 - 22)  # 54 bytes
        return header + descriptor

    def test_read_im0(self, mock_rpc):
        """Test reading I&M0 data."""
        payload = self._create_im0_payload()
        mock_iod = MagicMock()
        mock_iod.payload = payload
        mock_rpc.read = MagicMock(return_value=mock_iod)

        im0 = mock_rpc.read_im0()
        # vendor_id is combined from vendor_id_high and vendor_id_low
        assert im0.vendor_id_high == 0x00
        assert im0.vendor_id_low == 0x2A
        mock_rpc.read.assert_called_once()

    def test_read_im1(self, mock_rpc):
        """Test reading I&M1 data."""
        payload = self._create_im1_payload()
        mock_iod = MagicMock()
        mock_iod.payload = payload
        mock_rpc.read = MagicMock(return_value=mock_iod)

        im1 = mock_rpc.read_im1()
        assert b"TAG-FUNCTION" in im1.im_tag_function
        mock_rpc.read.assert_called_once()

    def test_read_im2(self, mock_rpc):
        """Test reading I&M2 data."""
        payload = self._create_im2_payload()
        mock_iod = MagicMock()
        mock_iod.payload = payload
        mock_rpc.read = MagicMock(return_value=mock_iod)

        im2 = mock_rpc.read_im2()
        assert b"2024-01-15" in im2.im_date
        mock_rpc.read.assert_called_once()

    def test_read_im3(self, mock_rpc):
        """Test reading I&M3 data."""
        payload = self._create_im3_payload()
        mock_iod = MagicMock()
        mock_iod.payload = payload
        mock_rpc.read = MagicMock(return_value=mock_iod)

        im3 = mock_rpc.read_im3()
        assert b"Device Descriptor" in im3.im_descriptor
        mock_rpc.read.assert_called_once()

    def test_read_all_im_returns_dict(self, mock_rpc):
        """Test read_all_im returns dictionary with available records."""
        # Mock read to return I&M0 and fail for others
        im0_payload = self._create_im0_payload()
        mock_iod = MagicMock()
        mock_iod.payload = im0_payload

        from profinet.exceptions import RPCError

        call_count = [0]

        def mock_read(api, slot, subslot, idx):
            call_count[0] += 1
            if idx == 0xAFF0:  # I&M0
                return mock_iod
            raise RPCError("Not supported")

        mock_rpc.read = mock_read

        result = mock_rpc.read_all_im()
        assert isinstance(result, dict)
        assert "im0" in result


class TestPortMethods:
    """Test port and interface methods."""

    @pytest.fixture
    def mock_rpc(self):
        """Create a mocked RPCCon instance."""
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 100, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
        }
        info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", blocks)
        with patch("profinet.rpc.socket"):
            rpc = RPCCon(info)
            yield rpc
            rpc.close()

    def test_read_port_statistics(self, mock_rpc):
        """Test reading port statistics."""
        # Minimal payload
        header = pack(">HH", 0x8028, 30) + bytes([0x01, 0x00])
        payload = header + bytes(24)

        mock_iod = MagicMock()
        mock_iod.payload = payload
        mock_rpc.read = MagicMock(return_value=mock_iod)

        stats = mock_rpc.read_port_statistics()
        assert isinstance(stats, PortStatistics)

    def test_read_link_data_with_mau_type(self, mock_rpc):
        """Test reading link data with MAU type parsing."""
        # Create payload with MAU type 16 (100BASE-TX FD)
        header = pack(">HH", 0x8029, 14) + bytes([0x01, 0x00])
        # 2 bytes padding + MAU type at offset 8-10
        payload = header + bytes([0, 0]) + pack(">H", 16) + bytes(4)

        mock_iod = MagicMock()
        mock_iod.payload = payload
        mock_rpc.read = MagicMock(return_value=mock_iod)

        link = mock_rpc.read_link_data()
        assert isinstance(link, LinkData)
        assert link.mau_type == 16
        assert link.mau_type_name == "100BASE-TX FD"

    def test_read_interface_info(self, mock_rpc):
        """Test reading interface information."""
        # Build interface info block
        header = pack(">HH", 0x8080, 40) + bytes([0x01, 0x00])
        chassis_name = b"test-chassis"
        content = bytes([len(chassis_name)]) + chassis_name
        # Add padding for alignment
        if len(content) % 2:
            content += bytes([0])
        content += bytes([0, 0])  # padding
        # MAC address
        content += bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        content += bytes([0, 0])  # padding
        # IP, netmask, gateway
        content += bytes([192, 168, 1, 100])  # IP
        content += bytes([255, 255, 255, 0])  # netmask
        content += bytes([192, 168, 1, 1])  # gateway

        payload = header + content

        mock_iod = MagicMock()
        mock_iod.payload = payload
        mock_rpc.read = MagicMock(return_value=mock_iod)

        info = mock_rpc.read_interface_info()
        assert isinstance(info, InterfaceInfo)
        assert info.chassis_id == "test-chassis"

    def test_read_port_info(self, mock_rpc):
        """Test reading port information."""
        # Build port info block
        header = pack(">HH", 0x802A, 30) + bytes([0x01, 0x00])
        content = bytes([0, 0])  # padding
        content += pack(">H", 0)  # slot
        content += pack(">H", 0x8001)  # subslot
        port_id = b"port-001"
        content += bytes([len(port_id)]) + port_id

        payload = header + content

        mock_iod = MagicMock()
        mock_iod.payload = payload
        mock_rpc.read = MagicMock(return_value=mock_iod)

        port = mock_rpc.read_port_info()
        assert isinstance(port, PortInfo)
        assert port.subslot == 0x8001
        assert port.port_id == "port-001"


class TestDiagnosticMethods:
    """Test diagnostic and logbook methods."""

    @pytest.fixture
    def mock_rpc(self):
        """Create a mocked RPCCon instance."""
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 100, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
        }
        info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", blocks)
        with patch("profinet.rpc.socket"):
            rpc = RPCCon(info)
            yield rpc
            rpc.close()

    def test_read_diagnosis_returns_diagnosis_data(self, mock_rpc):
        """Test read_diagnosis returns DiagnosisData object."""
        from profinet.diagnosis import DiagnosisData

        header = pack(">HH", 0xF000, 20) + bytes([0x01, 0x00])
        payload = header + bytes(14)

        mock_iod = MagicMock()
        mock_iod.payload = payload
        mock_rpc.read = MagicMock(return_value=mock_iod)

        result = mock_rpc.read_diagnosis()
        assert isinstance(result, DiagnosisData)
        assert isinstance(result.entries, list)

    def test_read_diagnosis_error_returns_empty_diagnosis_data(self, mock_rpc):
        """Test read_diagnosis returns empty DiagnosisData on error."""
        from profinet.diagnosis import DiagnosisData
        from profinet.exceptions import RPCError

        mock_rpc.read = MagicMock(side_effect=RPCError("Not available"))

        result = mock_rpc.read_diagnosis()
        assert isinstance(result, DiagnosisData)
        assert result.entries == []

    def test_read_logbook_returns_list(self, mock_rpc):
        """Test read_logbook returns list of entries."""
        header = pack(">HH", 0xF830, 22) + bytes([0x01, 0x00])
        # Add log entries (timestamp + detail, 8 bytes each)
        entry1 = pack(">II", 1234567890, 0x00000001)
        entry2 = pack(">II", 1234567900, 0x00000002)
        payload = header + entry1 + entry2

        mock_iod = MagicMock()
        mock_iod.payload = payload
        mock_rpc.read = MagicMock(return_value=mock_iod)

        entries = mock_rpc.read_logbook()
        assert isinstance(entries, list)
        assert len(entries) == 2
        assert entries[0].timestamp == 1234567890
        assert entries[1].timestamp == 1234567900

    def test_read_logbook_error_returns_empty(self, mock_rpc):
        """Test read_logbook returns empty list on error."""
        from profinet.exceptions import RPCError

        mock_rpc.read = MagicMock(side_effect=RPCError("Not available"))

        entries = mock_rpc.read_logbook()
        assert entries == []

    def test_read_ar_info_returns_arinfo(self, mock_rpc):
        """Test read_ar_info returns ARInfo object."""
        header = pack(">HH", 0xF820, 30) + bytes([0x01, 0x00])
        # AR UUID (16 bytes with padding)
        content = bytes([0, 0])  # padding
        ar_uuid = bytes(range(16))
        content += ar_uuid
        content += pack(">H", 0x0006)  # AR type
        payload = header + content

        mock_iod = MagicMock()
        mock_iod.payload = payload
        mock_rpc.read = MagicMock(return_value=mock_iod)

        ar = mock_rpc.read_ar_info()
        assert isinstance(ar, ARInfo)
        assert ar.ar_type == 0x0006

    def test_read_ar_info_error_returns_none(self, mock_rpc):
        """Test read_ar_info returns None on error."""
        from profinet.exceptions import RPCError

        mock_rpc.read = MagicMock(side_effect=RPCError("Not available"))

        ar = mock_rpc.read_ar_info()
        assert ar is None


class TestRawMethods:
    """Test raw read methods."""

    @pytest.fixture
    def mock_rpc(self):
        """Create a mocked RPCCon instance."""
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 100, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
        }
        info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", blocks)
        with patch("profinet.rpc.socket"):
            rpc = RPCCon(info)
            yield rpc
            rpc.close()

    def test_read_raw_returns_bytes(self, mock_rpc):
        """Test read_raw returns raw payload bytes."""
        expected_payload = bytes([0xDE, 0xAD, 0xBE, 0xEF] * 10)
        mock_iod = MagicMock()
        mock_iod.payload = expected_payload
        mock_rpc.read = MagicMock(return_value=mock_iod)

        result = mock_rpc.read_raw(idx=0xAFF0)
        assert result == expected_payload

    def test_read_raw_custom_slot_subslot(self, mock_rpc):
        """Test read_raw with custom slot/subslot."""
        mock_iod = MagicMock()
        mock_iod.payload = bytes(10)
        mock_rpc.read = MagicMock(return_value=mock_iod)

        mock_rpc.read_raw(idx=0xAFF0, slot=1, subslot=0x8001)
        mock_rpc.read.assert_called_with(api=0, slot=1, subslot=0x8001, idx=0xAFF0)


class TestErrorHandling:
    """Test error handling in RPC operations."""

    @pytest.fixture
    def mock_rpc(self):
        """Create a mocked RPCCon instance."""
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 100, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
        }
        info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", blocks)
        with patch("profinet.rpc.socket"):
            rpc = RPCCon(info)
            yield rpc
            rpc.close()

    def test_connect_requires_src_mac(self, mock_rpc):
        """Test connect raises ValueError without src_mac."""
        with pytest.raises(ValueError, match="src_mac required"):
            mock_rpc.connect()

    def test_connect_accepts_src_mac(self, mock_rpc):
        """Test connect accepts src_mac parameter."""

        from profinet.exceptions import RPCConnectionError

        mock_rpc._socket.recvfrom = MagicMock(side_effect=TimeoutError())

        with pytest.raises(RPCConnectionError):
            mock_rpc.connect(src_mac=b"\x00\x11\x22\x33\x44\x55")


class TestGetStationInfo:
    """Test get_station_info function."""

    def test_get_station_info_not_found(self):
        """Test get_station_info raises error when device not found."""
        from profinet.exceptions import DCPDeviceNotFoundError

        mock_sock = MagicMock()

        with patch("profinet.rpc.dcp.send_request"):
            with patch("profinet.rpc.dcp.read_response", return_value={}):
                with pytest.raises(DCPDeviceNotFoundError, match="not found"):
                    get_station_info(mock_sock, b"\x00\x11\x22\x33\x44\x55", "unknown-device")

    def test_get_station_info_found(self):
        """Test get_station_info returns device description."""
        mock_sock = MagicMock()
        mock_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        mock_blocks = {
            PNDCPBlock.NAME_OF_STATION: b"found-device",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 100, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
        }

        with patch("profinet.rpc.dcp.send_request"):
            with patch("profinet.rpc.dcp.read_response", return_value={mock_mac: mock_blocks}):
                info = get_station_info(mock_sock, b"\x00\x11\x22\x33\x44\x55", "found-device")
                assert info.name == "found-device"
                assert info.ip == "192.168.1.100"


from profinet.rpc import (
    PNIO_DEVICE_INTERFACE_VERSION,
    RPC_BIND_PORT,
    RPC_PORT,
    UUID_EPM_V4,
    UUID_NULL,
    UUID_PNIO_CONTROLLER,
    UUID_PNIO_DEVICE,
    EPMEndpoint,
    _parse_epm_tower,
    _string_to_uuid_bytes,
    _uuid_bytes_to_string,
    epm_lookup,
)


class TestRPCConstants:
    """Test RPC port and UUID constants."""

    def test_rpc_port_value(self):
        """Test RPC port is 0x8894 (34964)."""
        assert RPC_PORT == 0x8894
        assert RPC_PORT == 34964

    def test_rpc_bind_port_value(self):
        """Test RPC bind port is 0x8895 (34965)."""
        assert RPC_BIND_PORT == 0x8895
        assert RPC_BIND_PORT == 34965

    def test_uuid_null_value(self):
        """Test NULL UUID constant."""
        assert UUID_NULL == "00000000-0000-0000-0000-000000000000"

    def test_uuid_epm_v4_value(self):
        """Test Endpoint Mapper v4 UUID."""
        assert UUID_EPM_V4 == "e1af8308-5d1f-11c9-91a4-08002b14a0fa"

    def test_uuid_pnio_device_value(self):
        """Test PROFINET IO Device UUID."""
        assert UUID_PNIO_DEVICE == "dea00001-6c97-11d1-8271-00a02442df7d"

    def test_uuid_pnio_controller_value(self):
        """Test PROFINET IO Controller UUID."""
        assert UUID_PNIO_CONTROLLER == "dea00002-6c97-11d1-8271-00a02442df7d"

    def test_pnio_interface_version(self):
        """Test PNIO Device Interface version."""
        assert PNIO_DEVICE_INTERFACE_VERSION == 1

    def test_uuid_device_and_controller_differ_only_in_last_digit(self):
        """Test PNIO Device and Controller UUIDs differ only in last digit."""
        # They should have the same prefix, differ only in 00001 vs 00002
        assert UUID_PNIO_DEVICE[:-1] == "dea00001-6c97-11d1-8271-00a02442df7"
        assert UUID_PNIO_CONTROLLER[:-1] == "dea00002-6c97-11d1-8271-00a02442df7"


class TestRPCConstantsExport:
    """Test RPC constants are exported correctly."""

    def test_rpc_port_importable_from_package(self):
        """Test RPC_PORT can be imported from profinet package."""
        from profinet import RPC_PORT

        assert RPC_PORT == 0x8894

    def test_rpc_bind_port_importable_from_package(self):
        """Test RPC_BIND_PORT can be imported from profinet package."""
        from profinet import RPC_BIND_PORT

        assert RPC_BIND_PORT == 0x8895

    def test_uuid_epm_v4_importable_from_package(self):
        """Test UUID_EPM_V4 can be imported from profinet package."""
        from profinet import UUID_EPM_V4

        assert UUID_EPM_V4 == "e1af8308-5d1f-11c9-91a4-08002b14a0fa"

    def test_uuid_pnio_device_importable_from_package(self):
        """Test UUID_PNIO_DEVICE can be imported from profinet package."""
        from profinet import UUID_PNIO_DEVICE

        assert UUID_PNIO_DEVICE == "dea00001-6c97-11d1-8271-00a02442df7d"

    def test_uuid_pnio_controller_importable_from_package(self):
        """Test UUID_PNIO_CONTROLLER can be imported from profinet package."""
        from profinet import UUID_PNIO_CONTROLLER

        assert UUID_PNIO_CONTROLLER == "dea00002-6c97-11d1-8271-00a02442df7d"


class TestEPMEndpoint:
    """Test EPMEndpoint data class."""

    def test_epm_endpoint_defaults(self):
        """Test EPMEndpoint default values."""
        ep = EPMEndpoint()
        assert ep.interface_uuid == ""
        assert ep.interface_version_major == 0
        assert ep.interface_version_minor == 0
        assert ep.object_uuid == ""
        assert ep.protocol == ""
        assert ep.port == 0
        assert ep.address == ""
        assert ep.annotation == ""

    def test_epm_endpoint_values(self):
        """Test EPMEndpoint with values."""
        ep = EPMEndpoint(
            interface_uuid=UUID_PNIO_DEVICE,
            interface_version_major=1,
            interface_version_minor=0,
            protocol="ncadg_ip_udp",
            port=34964,
            address="192.168.1.100",
            annotation="S7-1500 6ES7 672-5DC01-0YA0",
        )
        assert ep.interface_uuid == UUID_PNIO_DEVICE
        assert ep.port == 34964
        assert ep.annotation == "S7-1500 6ES7 672-5DC01-0YA0"

    def test_interface_name_pnio_device(self):
        """Test interface_name property for PNIO Device."""
        ep = EPMEndpoint(interface_uuid=UUID_PNIO_DEVICE)
        assert ep.interface_name == "PNIO-Device"

    def test_interface_name_pnio_controller(self):
        """Test interface_name property for PNIO Controller."""
        ep = EPMEndpoint(interface_uuid=UUID_PNIO_CONTROLLER)
        assert ep.interface_name == "PNIO-Controller"

    def test_interface_name_epm(self):
        """Test interface_name property for EPM."""
        ep = EPMEndpoint(interface_uuid=UUID_EPM_V4)
        assert ep.interface_name == "EPM"

    def test_interface_name_unknown(self):
        """Test interface_name property for unknown UUID."""
        ep = EPMEndpoint(interface_uuid="12345678-1234-1234-1234-123456789abc")
        assert "Unknown" in ep.interface_name


class TestUUIDConversion:
    """Test UUID string/bytes conversion functions."""

    def test_uuid_bytes_to_string_pnio_device(self):
        """Test converting PNIO Device UUID bytes to string."""
        # PNIO Device UUID in DCE/RPC format (mixed-endian)
        uuid_bytes = bytes(
            [
                0x01,
                0x00,
                0xA0,
                0xDE,  # time_low (LE)
                0x97,
                0x6C,  # time_mid (LE)
                0xD1,
                0x11,  # time_hi (LE)
                0x82,
                0x71,  # clock_seq (BE)
                0x00,
                0xA0,
                0x24,
                0x42,
                0xDF,
                0x7D,  # node (BE)
            ]
        )
        result = _uuid_bytes_to_string(uuid_bytes)
        assert result == "dea00001-6c97-11d1-8271-00a02442df7d"

    def test_uuid_bytes_to_string_null(self):
        """Test converting NULL UUID bytes to string."""
        uuid_bytes = bytes(16)
        result = _uuid_bytes_to_string(uuid_bytes)
        assert result == "00000000-0000-0000-0000-000000000000"

    def test_uuid_bytes_to_string_invalid_length(self):
        """Test converting invalid length returns empty string."""
        result = _uuid_bytes_to_string(bytes(10))
        assert result == ""

    def test_string_to_uuid_bytes_pnio_device(self):
        """Test converting PNIO Device UUID string to bytes."""
        result = _string_to_uuid_bytes(UUID_PNIO_DEVICE)
        assert len(result) == 16
        # Verify round-trip
        assert _uuid_bytes_to_string(result) == UUID_PNIO_DEVICE

    def test_string_to_uuid_bytes_epm(self):
        """Test converting EPM UUID string to bytes."""
        result = _string_to_uuid_bytes(UUID_EPM_V4)
        assert len(result) == 16
        # Verify round-trip
        assert _uuid_bytes_to_string(result) == UUID_EPM_V4

    def test_string_to_uuid_bytes_invalid(self):
        """Test converting invalid UUID string raises error."""
        with pytest.raises(ValueError, match="Invalid UUID"):
            _string_to_uuid_bytes("invalid-uuid")

    def test_uuid_roundtrip(self):
        """Test UUID conversion roundtrip for various UUIDs."""
        uuids = [
            UUID_NULL,
            UUID_EPM_V4,
            UUID_PNIO_DEVICE,
            UUID_PNIO_CONTROLLER,
        ]
        for uuid_str in uuids:
            uuid_bytes = _string_to_uuid_bytes(uuid_str)
            result = _uuid_bytes_to_string(uuid_bytes)
            assert result == uuid_str, f"Roundtrip failed for {uuid_str}"


class TestParseEPMTower:
    """Test EPM tower parsing."""

    def test_parse_empty_tower(self):
        """Test parsing empty tower returns None."""
        result = _parse_epm_tower(b"")
        assert result is None

    def test_parse_short_tower(self):
        """Test parsing too short tower returns None."""
        result = _parse_epm_tower(bytes(3))
        assert result is None

    def test_parse_minimal_tower(self):
        """Test parsing minimal valid tower."""
        # Floor count = 0
        tower = bytes([0x00, 0x00])
        result = _parse_epm_tower(tower)
        # Should return None because no interface UUID was found
        assert result is None

    def test_parse_tower_with_uuid_floor(self):
        """Test parsing tower with UUID floor."""
        import struct

        # Build a simple tower with one UUID floor
        tower = bytearray()

        # Floor count = 1
        tower.extend(struct.pack("<H", 1))

        # Floor 1: UUID floor
        # LHS: protocol ID (0x0D) + UUID (16 bytes) + version (2 bytes) = 19 bytes
        lhs = bytes([0x0D])  # Protocol ID for UUID
        lhs += _string_to_uuid_bytes(UUID_PNIO_DEVICE)  # UUID
        lhs += struct.pack("<H", 1)  # Version major

        tower.extend(struct.pack("<H", len(lhs)))  # LHS length
        tower.extend(lhs)  # LHS data

        # RHS: version minor (2 bytes)
        rhs = struct.pack("<H", 0)  # Version minor
        tower.extend(struct.pack("<H", len(rhs)))  # RHS length
        tower.extend(rhs)  # RHS data

        result = _parse_epm_tower(bytes(tower))
        assert result is not None
        assert result.interface_uuid == UUID_PNIO_DEVICE
        assert result.interface_version_major == 1
        assert result.interface_version_minor == 0


class TestEPMLookup:
    """Test epm_lookup function."""

    def test_epm_lookup_timeout(self):
        """Test epm_lookup returns empty list on timeout."""
        # Use a non-routable IP to force timeout
        result = epm_lookup("192.0.2.1", timeout=0.5)  # TEST-NET-1
        assert result == []

    def test_epm_lookup_returns_list(self):
        """Test epm_lookup returns a list."""
        # Use localhost which should fail quickly
        result = epm_lookup("127.0.0.1", timeout=0.5)
        assert isinstance(result, list)

    def test_epm_lookup_importable(self):
        """Test epm_lookup is importable from package."""
        from profinet import epm_lookup as epm_func

        assert callable(epm_func)

    def test_epm_endpoint_importable(self):
        """Test EPMEndpoint is importable from package."""
        from profinet import EPMEndpoint as EPMClass

        ep = EPMClass()
        assert ep.port == 0


# ---------------------------------------------------------------------------
# Helper: build a minimal valid PNRPCHeader in bytes
# ---------------------------------------------------------------------------


def _build_rpc_bytes(packet_type=0x02, operation_number=0x02, payload=b""):
    """Build minimal valid PNRPCHeader bytes.

    Default is a RESPONSE packet (type=0x02) for READ (op=0x02).
    """
    # PNRPCHeader fixed fields (big-endian, 80 bytes total):
    #   version(B) packet_type(B) flags1(B) flags2(B) drep(3s) serial_high(B)
    #   object_uuid(16s) interface_uuid(16s) activity_uuid(16s)
    #   server_boot_time(I) interface_version(I) sequence_number(I)
    #   operation_number(H) interface_hint(H) activity_hint(H)
    #   length_of_body(H) fragment_number(H) auth_protocol(B) serial_low(B)
    body_len = len(payload)
    hdr = _struct.pack(
        ">BB BB 3s B 16s 16s 16s III HHH HH BB",
        0x04,  # version
        packet_type,
        0x00,  # flags1
        0x00,  # flags2
        b"\x00\x00\x00",  # drep (big-endian)
        0x00,  # serial_high
        b"\x00" * 16,  # object_uuid
        b"\x00" * 16,  # interface_uuid
        b"\x00" * 16,  # activity_uuid
        0,  # server_boot_time
        1,  # interface_version
        0,  # sequence_number
        operation_number,
        0xFFFF,  # interface_hint
        0xFFFF,  # activity_hint
        body_len,  # length_of_body
        0,  # fragment_number
        0,  # auth_protocol
        0,  # serial_low
    )
    return hdr + payload


class TestSendReceiveEchoSkip:
    """Test echo-skip logic in _send_receive."""

    @pytest.fixture
    def mock_rpc(self):
        """Create RPCCon with mocked sockets."""
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 100, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
        }
        info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", blocks)
        with patch("profinet.rpc.socket"):
            rpc = RPCCon(info, timeout=2.0)
            yield rpc
            rpc.close()

    def test_echo_skip_returns_response(self, mock_rpc):
        """REQUEST packet is skipped, RESPONSE packet is returned."""
        from profinet.protocol import PNRPCHeader

        request_bytes = _build_rpc_bytes(packet_type=PNRPCHeader.REQUEST)
        response_bytes = _build_rpc_bytes(packet_type=PNRPCHeader.RESPONSE)

        # recvfrom returns REQUEST first, then RESPONSE
        mock_rpc._socket.recvfrom = MagicMock(
            side_effect=[
                (request_bytes, ("192.168.1.100", 34964)),
                (response_bytes, ("192.168.1.100", 34964)),
            ]
        )
        mock_rpc._socket.sendto = MagicMock()

        # Build a minimal RPC request to pass to _send_receive
        rpc_req = PNRPCHeader(
            0x04,
            PNRPCHeader.REQUEST,
            0,
            0,
            b"\x00\x00\x00",
            0,
            b"\x00" * 16,
            b"\x00" * 16,
            b"\x00" * 16,
            0,
            1,
            0,
            PNRPCHeader.READ,
            0xFFFF,
            0xFFFF,
            0,
            0,
            0,
            0,
            payload=b"",
        )

        result = mock_rpc._send_receive(rpc_req)
        assert result.packet_type == PNRPCHeader.RESPONSE
        # recvfrom was called twice (REQUEST skipped, RESPONSE returned)
        assert mock_rpc._socket.recvfrom.call_count == 2

    def test_echo_skip_timeout(self, mock_rpc):
        """Only REQUEST packets arrive until deadline expires -> RPCTimeoutError."""
        from profinet.exceptions import RPCTimeoutError
        from profinet.protocol import PNRPCHeader

        request_bytes = _build_rpc_bytes(packet_type=PNRPCHeader.REQUEST)

        # Return REQUEST packets forever -- the deadline should stop the loop
        mock_rpc._socket.recvfrom = MagicMock(
            return_value=(request_bytes, ("192.168.1.100", 34964))
        )
        mock_rpc._socket.sendto = MagicMock()

        # Use a very short timeout so the test runs fast
        mock_rpc.timeout = 0.3

        rpc_req = PNRPCHeader(
            0x04,
            PNRPCHeader.REQUEST,
            0,
            0,
            b"\x00\x00\x00",
            0,
            b"\x00" * 16,
            b"\x00" * 16,
            b"\x00" * 16,
            0,
            1,
            0,
            PNRPCHeader.READ,
            0xFFFF,
            0xFFFF,
            0,
            0,
            0,
            0,
            payload=b"",
        )

        start = _time.monotonic()
        with pytest.raises(RPCTimeoutError):
            mock_rpc._send_receive(rpc_req)
        elapsed = _time.monotonic() - start

        # Should have timed out within roughly the timeout period
        assert elapsed < 2.0, f"Loop took too long: {elapsed:.1f}s"


class TestCControlSocketLifecycle:
    """Test CControl socket creation at init and cleanup at close."""

    def test_ccontrol_socket_created_at_init(self):
        """_ccontrol_socket is created and bound at init time."""
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 100, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
        }
        info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", blocks)

        with patch("profinet.rpc.socket") as mock_socket_cls:
            mock_main = MagicMock()
            mock_ccontrol = MagicMock()
            # First call creates the main socket, second creates CControl
            mock_socket_cls.side_effect = [mock_main, mock_ccontrol]

            rpc = RPCCon(info)
            assert rpc._ccontrol_socket is mock_ccontrol
            mock_ccontrol.bind.assert_called_once_with(("", 0x8894))
            rpc.close()

    def test_ccontrol_socket_closed_on_close(self):
        """_ccontrol_socket is closed when close() is called."""
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 100, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
        }
        info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", blocks)

        with patch("profinet.rpc.socket") as mock_socket_cls:
            mock_main = MagicMock()
            mock_ccontrol = MagicMock()
            mock_socket_cls.side_effect = [mock_main, mock_ccontrol]

            rpc = RPCCon(info)
            assert rpc._ccontrol_socket is not None
            rpc.close()
            mock_ccontrol.close.assert_called_once()
            assert rpc._ccontrol_socket is None

    def test_ccontrol_socket_fallback_on_bind_failure(self):
        """If bind fails at init, _ccontrol_socket is None (fallback)."""
        blocks = {
            PNDCPBlock.NAME_OF_STATION: b"test-device",
            PNDCPBlock.IP_ADDRESS: bytes([192, 168, 1, 100, 255, 255, 255, 0, 192, 168, 1, 1]),
            PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
        }
        info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", blocks)

        with patch("profinet.rpc.socket") as mock_socket_cls:
            mock_main = MagicMock()
            mock_ccontrol = MagicMock()
            mock_ccontrol.bind.side_effect = OSError("Address already in use")
            mock_socket_cls.side_effect = [mock_main, mock_ccontrol]

            rpc = RPCCon(info)
            assert rpc._ccontrol_socket is None
            rpc.close()
