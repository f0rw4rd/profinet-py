"""Tests for PROFINET block parsing module."""

import struct

import pytest

from profinet import blocks, indices


class TestBlockHeader:
    """Tests for BlockHeader parsing."""

    def test_parse_block_header_valid(self):
        """Test parsing a valid 6-byte block header."""
        # BlockType=0x0400 (MultipleBlockHeader), Length=0x0090, Version=1.0
        data = struct.pack(">HHBB", 0x0400, 0x0090, 0x01, 0x00)
        header, offset = blocks.parse_block_header(data)

        assert header.block_type == 0x0400
        assert header.block_length == 0x0090
        assert header.version_high == 1
        assert header.version_low == 0
        assert header.body_length == 0x008E  # 0x0090 - 2
        assert offset == 6

    def test_parse_block_header_short_data(self):
        """Test error handling for truncated data."""
        data = b"\x04\x00\x00"  # Only 3 bytes
        with pytest.raises(ValueError, match="requires 6 bytes"):
            blocks.parse_block_header(data)

    def test_parse_block_header_with_offset(self):
        """Test parsing with non-zero offset."""
        prefix = b"\xff\xff\xff\xff"  # 4 bytes of padding
        header_data = struct.pack(">HHBB", 0x0240, 0x0024, 0x01, 0x00)
        data = prefix + header_data

        header, offset = blocks.parse_block_header(data, 4)

        assert header.block_type == 0x0240
        assert header.block_length == 0x0024
        assert offset == 10  # 4 + 6

    def test_block_header_type_name(self):
        """Test block type name lookup."""
        data = struct.pack(">HHBB", indices.BLOCK_MULTIPLE_HEADER, 0x0010, 1, 0)
        header, _ = blocks.parse_block_header(data)
        assert header.type_name == "MultipleBlockHeader"

        data = struct.pack(">HHBB", 0x9999, 0x0010, 1, 0)
        header, _ = blocks.parse_block_header(data)
        assert "Unknown" in header.type_name


class TestMultipleBlockHeader:
    """Tests for MultipleBlockHeader (0x0400) parsing."""

    def test_parse_multiple_block_header(self):
        """Test parsing MultipleBlockHeader body."""
        # 2 bytes padding + API(4) + Slot(2) + Subslot(2)
        data = struct.pack(">xxIHH", 0x00000000, 0x0000, 0x8000)
        api, slot, subslot, body_offset = blocks.parse_multiple_block_header(data)

        assert api == 0
        assert slot == 0
        assert subslot == 0x8000
        assert body_offset == 10  # 2 (padding) + 8 (api+slot+subslot)

    def test_parse_multiple_block_header_nonzero_api(self):
        """Test parsing with non-zero API."""
        data = struct.pack(">xxIHH", 0x00000001, 0x0002, 0x0001)
        api, slot, subslot, _ = blocks.parse_multiple_block_header(data)

        assert api == 1
        assert slot == 2
        assert subslot == 1

    def test_parse_multiple_block_header_truncated(self):
        """Test error on truncated data."""
        data = b"\x00\x00\x00\x00"  # Only 4 bytes
        with pytest.raises(ValueError, match="requires 8 bytes"):
            blocks.parse_multiple_block_header(data)


class TestPDInterfaceDataReal:
    """Tests for PDInterfaceDataReal (0x0240) parsing."""

    def test_parse_interface_data(self):
        """Test parsing PDInterfaceDataReal block body.

        Alignment is relative to block start (6-byte header + body).
        For a 10-byte chassis ID: header(6) + len(1) + chassis(10) = 17
        Align to 4 -> 20, so MAC starts at body offset 14 (3 bytes padding).
        """
        # Real device format: chassis_len=10, 3 bytes padding, MAC, 2 bytes padding, IP/Subnet/GW
        # Using chassis "AAAAAAAAAA" (10 bytes) to match real alignment
        data = bytes.fromhex(
            "0A"  # chassis_len = 10
            "41414141414141414141"  # "AAAAAAAAAA" (10 bytes)
            "000000"  # 3 bytes padding (block offset 17 -> 20)
            "001122334455"  # MAC (6 bytes, block offset 20-25)
            "0000"  # 2 bytes padding (block offset 26 -> 28)
            "C0A80164"  # IP: 192.168.1.100
            "FFFFFF00"  # Subnet: 255.255.255.0
            "C0A80101"  # Gateway: 192.168.1.1
        )

        info = blocks.parse_pd_interface_data_real(data)

        assert info.chassis_id == "AAAAAAAAAA"
        assert info.mac_address == b"\x00\x11\x22\x33\x44\x55"
        assert info.ip_str == "192.168.1.100"
        assert info.subnet_str == "255.255.255.0"
        assert info.gateway_str == "192.168.1.1"

    def test_interface_info_mac_str(self):
        """Test MAC address string formatting."""
        info = blocks.InterfaceInfo(
            chassis_id="test",
            mac_address=b"\xab\xcd\xef\x01\x23\x45",
            ip_address=b"\x00\x00\x00\x00",
            subnet_mask=b"\x00\x00\x00\x00",
            gateway=b"\x00\x00\x00\x00",
        )
        assert info.mac_str == "ab:cd:ef:01:23:45"


class TestPDPortDataReal:
    """Tests for PDPortDataReal (0x020F) parsing."""

    def test_parse_port_data_minimal(self):
        """Test parsing minimal port data."""
        # Slot(2) + Subslot(2) + PortIDLen(1) + PortID + NumPeers(1)
        port_id = b"port-001"
        data = struct.pack(">HH", 0, 0x8001) + bytes([len(port_id)]) + port_id + b"\x00"

        port = blocks.parse_pd_port_data_real(data, slot=0, subslot=0x8001)

        assert port.slot == 0
        assert port.subslot == 0x8001
        assert port.port_id == "port-001"
        assert len(port.peers) == 0

    def test_parse_port_data_with_peer(self):
        """Test parsing port data with peer information."""
        # Build test data with one peer
        port_id = b"port-001"
        peer_port = b"port-002"
        peer_chassis = b"peer-dev"
        peer_mac = b"\x00\x11\x22\x33\x44\x66"

        data = bytearray()
        # Slot/Subslot
        data.extend(struct.pack(">HH", 0, 0x8001))
        # Port ID
        data.append(len(port_id))
        data.extend(port_id)
        # Number of peers
        data.append(1)
        # Padding to 4-byte boundary
        while len(data) % 4:
            data.append(0)
        # Peer port ID
        data.append(len(peer_port))
        data.extend(peer_port)
        # Peer chassis ID
        data.append(len(peer_chassis))
        data.extend(peer_chassis)
        # Padding
        while len(data) % 4:
            data.append(0)
        # Peer MAC
        data.extend(peer_mac)
        # Padding
        while len(data) % 4:
            data.append(0)
        # MAU type
        data.extend(struct.pack(">H", 16))  # 100BaseTX
        # Padding
        while len(data) % 4:
            data.append(0)

        port = blocks.parse_pd_port_data_real(bytes(data))

        assert port.port_id == "port-001"
        assert len(port.peers) == 1
        assert port.peers[0].port_id == "port-002"
        assert port.peers[0].chassis_id == "peer-dev"


class TestSlotInfo:
    """Tests for SlotInfo data class."""

    def test_slot_info_repr(self):
        """Test SlotInfo string representation."""
        slot = blocks.SlotInfo(api=0, slot=1, subslot=0x8001)
        assert "api=0" in repr(slot)
        assert "slot=1" in repr(slot)
        assert "0x8001" in repr(slot)

    def test_slot_info_with_idents(self):
        """Test SlotInfo with module/submodule identifiers."""
        slot = blocks.SlotInfo(
            api=0,
            slot=0,
            subslot=1,
            module_ident=0x12345678,
            submodule_ident=0x00000001,
        )
        assert slot.module_ident == 0x12345678
        assert slot.submodule_ident == 0x00000001


class TestPDRealData:
    """Tests for PDRealData (0xF841) parsing."""

    def test_parse_empty_data(self):
        """Test parsing empty data returns empty result."""
        result = blocks.parse_pd_real_data(b"")
        assert len(result.slots) == 0
        assert result.interface is None
        assert len(result.ports) == 0

    def test_parse_single_multiple_block(self):
        """Test parsing PDRealData with single MultipleBlockHeader."""
        # Build a MultipleBlockHeader (0x0400) containing PDInterfaceDataReal (0x0240)
        # Outer block header
        outer_data = bytearray()

        # MultipleBlockHeader header: type=0x0400, length=TBD, version=1.0
        outer_data.extend(struct.pack(">HHBB", 0x0400, 0, 1, 0))
        # Padding (2 bytes) + API(4) + Slot(2) + Subslot(2)
        outer_data.extend(struct.pack(">xxIHH", 0, 0, 0x8000))

        # Nested PDInterfaceDataReal (0x0240)
        inner_data = bytearray()
        chassis = b"test"
        inner_data.append(len(chassis))
        inner_data.extend(chassis)
        # Padding
        while len(inner_data) % 4:
            inner_data.append(0)
        # MAC
        inner_data.extend(b"\x00\x11\x22\x33\x44\x55")
        # Padding
        while len(inner_data) % 4:
            inner_data.append(0)
        # IP/Subnet/GW
        inner_data.extend(b"\xc0\xa8\x01\x01")
        inner_data.extend(b"\xff\xff\xff\x00")
        inner_data.extend(b"\xc0\xa8\x01\x01")

        # Inner block header
        inner_header = struct.pack(">HHBB", 0x0240, len(inner_data) + 2, 1, 0)

        # Combine
        outer_data.extend(inner_header)
        outer_data.extend(inner_data)

        # Update outer block length
        outer_length = len(outer_data) - 4  # Exclude type and length fields
        struct.pack_into(">H", outer_data, 2, outer_length)

        result = blocks.parse_pd_real_data(bytes(outer_data))

        assert len(result.slots) == 1
        assert result.slots[0].slot == 0
        assert result.slots[0].subslot == 0x8000
        assert result.interface is not None
        assert result.interface.chassis_id == "test"


class TestRealIdentificationData:
    """Tests for RealIdentificationData (0xF000/0x0013) parsing."""

    def test_parse_version_1_0(self):
        """Test parsing RealIdentificationData version 1.0."""
        # Block header: type=0x0013, length, version=1.0
        data = bytearray()
        data.extend(struct.pack(">HHBB", 0x0013, 0, 1, 0))

        # NumberOfSlots = 2
        data.extend(struct.pack(">H", 2))

        # Slot 0: SlotNumber(2) + ModuleIdent(4) + NumSubslots(2)
        data.extend(struct.pack(">HIH", 0, 0x00010001, 2))
        # Subslot 1
        data.extend(struct.pack(">HI", 1, 0x00000001))
        # Subslot 0x8000
        data.extend(struct.pack(">HI", 0x8000, 0x00000002))

        # Slot 1: SlotNumber(2) + ModuleIdent(4) + NumSubslots(2)
        data.extend(struct.pack(">HIH", 1, 0x00020002, 1))
        # Subslot 1
        data.extend(struct.pack(">HI", 1, 0x00000001))

        # Update length
        struct.pack_into(">H", data, 2, len(data) - 4)

        result = blocks.parse_real_identification_data(bytes(data))

        assert result.version == (1, 0)
        assert len(result.slots) == 3  # 2 + 1 subslots total
        assert result.slots[0].slot == 0
        assert result.slots[0].subslot == 1
        assert result.slots[1].slot == 0
        assert result.slots[1].subslot == 0x8000
        assert result.slots[2].slot == 1
        assert result.slots[2].subslot == 1

    def test_parse_version_1_1_with_api(self):
        """Test parsing RealIdentificationData version 1.1 with API."""
        # Block header: type=0x0013, length, version=1.1
        data = bytearray()
        data.extend(struct.pack(">HHBB", 0x0013, 0, 1, 1))

        # NumberOfAPIs = 1
        data.extend(struct.pack(">H", 1))

        # API = 0
        data.extend(struct.pack(">I", 0))

        # NumberOfSlots = 1
        data.extend(struct.pack(">H", 1))

        # Slot 0: SlotNumber(2) + ModuleIdent(4) + NumSubslots(2)
        data.extend(struct.pack(">HIH", 0, 0x12345678, 1))
        # Subslot 1
        data.extend(struct.pack(">HI", 1, 0x87654321))

        # Update length
        struct.pack_into(">H", data, 2, len(data) - 4)

        result = blocks.parse_real_identification_data(bytes(data))

        assert result.version == (1, 1)
        assert len(result.slots) == 1
        assert result.slots[0].api == 0
        assert result.slots[0].slot == 0
        assert result.slots[0].subslot == 1
        assert result.slots[0].module_ident == 0x12345678
        assert result.slots[0].submodule_ident == 0x87654321

    def test_parse_empty_returns_empty(self):
        """Test parsing empty data returns empty result."""
        result = blocks.parse_real_identification_data(b"")
        assert len(result.slots) == 0


class TestPortStatistics:
    """Tests for PDPortStatistic (0x0251) parsing."""

    def test_parse_port_statistics(self):
        """Test parsing port statistics block."""
        # CounterStatus(2) + 6x uint32
        data = struct.pack(
            ">HIIIIII",
            0x0001,  # counter_status
            1000,  # ifInOctets
            2000,  # ifOutOctets
            5,  # ifInDiscards
            3,  # ifOutDiscards
            1,  # ifInErrors
            2,  # ifOutErrors
        )

        result = blocks.parse_port_statistics(data)

        assert result["counter_status"] == 1
        assert result["in_octets"] == 1000
        assert result["out_octets"] == 2000
        assert result["in_discards"] == 5
        assert result["out_discards"] == 3
        assert result["in_errors"] == 1
        assert result["out_errors"] == 2

    def test_parse_port_statistics_truncated(self):
        """Test parsing truncated data returns empty dict."""
        data = b"\x00\x01"  # Only 2 bytes
        result = blocks.parse_port_statistics(data)
        assert result == {}


class TestBlockTypeConstants:
    """Tests for block type constants in indices module."""

    def test_block_type_constants_defined(self):
        """Test that all expected block type constants are defined."""
        assert indices.BLOCK_MULTIPLE_HEADER == 0x0400
        assert indices.BLOCK_PD_PORT_DATA_REAL == 0x020F
        assert indices.BLOCK_PD_INTERFACE_DATA_REAL == 0x0240
        assert indices.BLOCK_PD_REAL_DATA == 0xF841
        assert indices.BLOCK_REAL_IDENTIFICATION_DATA == 0x0013
        assert indices.BLOCK_REAL_IDENTIFICATION_DATA_API == 0xF000

    def test_get_block_type_name(self):
        """Test block type name lookup function."""
        assert indices.get_block_type_name(0x0400) == "MultipleBlockHeader"
        assert indices.get_block_type_name(0x020F) == "PDPortDataReal"
        assert indices.get_block_type_name(0x0240) == "PDInterfaceDataReal"
        assert "Unknown" in indices.get_block_type_name(0xFFFF)

    def test_block_type_names_dict(self):
        """Test BLOCK_TYPE_NAMES dictionary."""
        assert indices.BLOCK_TYPE_NAMES[indices.BLOCK_IM0] == "I&M0"
        assert indices.BLOCK_TYPE_NAMES[indices.BLOCK_AR_DATA] == "ARData"
        assert indices.BLOCK_TYPE_NAMES[indices.BLOCK_LOG_DATA] == "LogData"


class TestAlign4:
    """Tests for the align4 helper function."""

    def test_align4_already_aligned(self):
        """Test align4 with already aligned values."""
        assert blocks.align4(0) == 0
        assert blocks.align4(4) == 4
        assert blocks.align4(8) == 8

    def test_align4_needs_padding(self):
        """Test align4 with values needing padding."""
        assert blocks.align4(1) == 4
        assert blocks.align4(2) == 4
        assert blocks.align4(3) == 4
        assert blocks.align4(5) == 8
        assert blocks.align4(6) == 8
        assert blocks.align4(7) == 8


# =============================================================================
# Integration Tests with Real Device Data
# =============================================================================


class TestRealDeviceData:
    """Tests using captured data from real PROFINET devices (anonymized)."""

    # PDRealData sample (anonymized - device names replaced)
    PDREALDATA_SAMPLE = bytes.fromhex(
        # MultipleBlockHeader for interface (slot 0, subslot 0x8000)
        "04000090"  # type=0x0400, length=0x0090
        "01000000"  # version 1.0, padding
        "00000000"  # API = 0
        "00008000"  # slot=0, subslot=0x8000
        # Nested PDInterfaceDataReal (0x0240)
        "0240"  # type
        "0024"  # length
        "0100"  # version
        "0a"  # chassis_id len = 10
        "41414141414141414141"  # "AAAAAAAAAA" (anonymized)
        "0000"  # padding
        "001122334455"  # MAC (anonymized)
        "0000"  # padding
        "c0a80164"  # IP: 192.168.1.100
        "ffffff00"  # Subnet: 255.255.255.0
        "c0a80101"  # Gateway: 192.168.1.1
    )

    def test_parse_real_pdrealdata_sample(self):
        """Test parsing simplified real device PDRealData."""
        # Note: This is a simplified sample, real data would be longer
        result = blocks.parse_pd_real_data(self.PDREALDATA_SAMPLE)

        # Should have at least one slot discovered
        assert len(result.slots) >= 1

        # First slot should be interface (subslot 0x8000)
        if result.slots:
            assert result.slots[0].subslot == 0x8000

    # RealIdentificationData sample (version 1.1, anonymized)
    REAL_ID_SAMPLE = bytes.fromhex(
        "00130046"  # type=0x0013, length=0x0046
        "0101"  # version 1.1
        "0001"  # NumAPIs = 1
        "00000000"  # API = 0
        "0003"  # NumSlots = 3
        # Slot 0
        "0000"  # SlotNumber = 0
        "00010001"  # ModuleIdent
        "0003"  # NumSubslots = 3
        "0001"
        "00000001"  # Subslot 1
        "8000"
        "00000002"  # Subslot 0x8000
        "8001"
        "00000003"  # Subslot 0x8001
        # Slot 1
        "0001"  # SlotNumber = 1
        "00020002"  # ModuleIdent
        "0001"  # NumSubslots = 1
        "0001"
        "00000001"  # Subslot 1
        # Slot 2
        "0002"  # SlotNumber = 2
        "00030003"  # ModuleIdent
        "0001"  # NumSubslots = 1
        "0001"
        "00000001"  # Subslot 1
    )

    def test_parse_real_identification_sample(self):
        """Test parsing real device RealIdentificationData."""
        result = blocks.parse_real_identification_data(self.REAL_ID_SAMPLE)

        assert result.version == (1, 1)
        # Should find 5 slot/subslot combinations (3+1+1)
        assert len(result.slots) == 5

        # Check first slot (slot 0, subslot 1)
        assert result.slots[0].slot == 0
        assert result.slots[0].subslot == 1
        assert result.slots[0].api == 0

        # Check interface subslot (slot 0, subslot 0x8000)
        assert result.slots[1].subslot == 0x8000

        # Check port subslot (slot 0, subslot 0x8001)
        assert result.slots[2].subslot == 0x8001


# =============================================================================
# ModuleDiffBlock (0x8104) Tests
# =============================================================================


class TestModuleDiffSubmodule:
    """Tests for ModuleDiffSubmodule data class."""

    def test_state_name_ok(self):
        """Test state_name for OK submodule."""
        sub = blocks.ModuleDiffSubmodule(
            subslot_number=1,
            submodule_ident_number=0x00000001,
            submodule_state=indices.SUBMODULE_STATE_OK,
        )
        assert sub.state_name == "OK"
        assert sub.is_ok is True

    def test_state_name_wrong(self):
        """Test state_name for wrong submodule."""
        sub = blocks.ModuleDiffSubmodule(
            subslot_number=1,
            submodule_ident_number=0x00000001,
            submodule_state=indices.SUBMODULE_STATE_WRONG_SUBMODULE,
        )
        assert sub.state_name == "WrongSubmodule"
        assert sub.is_ok is False

    def test_state_name_unknown(self):
        """Test state_name for unknown state value."""
        sub = blocks.ModuleDiffSubmodule(submodule_state=0xBEEF)
        assert "Unknown" in sub.state_name
        assert "0xBEEF" in sub.state_name

    def test_no_submodule_state(self):
        """Test NoSubmodule state."""
        sub = blocks.ModuleDiffSubmodule(
            submodule_state=indices.SUBMODULE_STATE_NO_SUBMODULE,
        )
        assert sub.state_name == "NoSubmodule"
        assert sub.is_ok is False


class TestModuleDiffModule:
    """Tests for ModuleDiffModule data class."""

    def test_state_name_proper(self):
        """Test state_name for proper module."""
        mod = blocks.ModuleDiffModule(
            api=0,
            slot_number=1,
            module_ident_number=0x00010001,
            module_state=indices.MODULE_STATE_PROPER_MODULE,
        )
        assert mod.state_name == "ProperModule"
        assert mod.is_proper is True

    def test_state_name_wrong(self):
        """Test state_name for wrong module."""
        mod = blocks.ModuleDiffModule(
            module_state=indices.MODULE_STATE_WRONG_MODULE,
        )
        assert mod.state_name == "WrongModule"
        assert mod.is_proper is False

    def test_state_name_unknown(self):
        """Test state_name for unknown state value."""
        mod = blocks.ModuleDiffModule(module_state=0xDEAD)
        assert "Unknown" in mod.state_name


class TestModuleDiffBlock:
    """Tests for ModuleDiffBlock data class and parsing."""

    def test_all_ok_empty(self):
        """Test all_ok returns True for empty module list."""
        diff = blocks.ModuleDiffBlock(modules=[])
        assert diff.all_ok is True

    def test_all_ok_proper_and_ok(self):
        """Test all_ok returns True when all modules are proper and submodules OK."""
        diff = blocks.ModuleDiffBlock(
            modules=[
                blocks.ModuleDiffModule(
                    slot_number=0,
                    module_state=indices.MODULE_STATE_PROPER_MODULE,
                    submodules=[
                        blocks.ModuleDiffSubmodule(
                            subslot_number=1,
                            submodule_state=indices.SUBMODULE_STATE_OK,
                        ),
                    ],
                ),
            ]
        )
        assert diff.all_ok is True

    def test_all_ok_wrong_module(self):
        """Test all_ok returns False when a module is wrong."""
        diff = blocks.ModuleDiffBlock(
            modules=[
                blocks.ModuleDiffModule(
                    slot_number=0,
                    module_state=indices.MODULE_STATE_WRONG_MODULE,
                ),
            ]
        )
        assert diff.all_ok is False

    def test_all_ok_wrong_submodule(self):
        """Test all_ok returns False when a submodule is wrong."""
        diff = blocks.ModuleDiffBlock(
            modules=[
                blocks.ModuleDiffModule(
                    slot_number=0,
                    module_state=indices.MODULE_STATE_PROPER_MODULE,
                    submodules=[
                        blocks.ModuleDiffSubmodule(
                            subslot_number=1,
                            submodule_state=indices.SUBMODULE_STATE_WRONG_SUBMODULE,
                        ),
                    ],
                ),
            ]
        )
        assert diff.all_ok is False

    def test_get_mismatches_empty(self):
        """Test get_mismatches returns empty for all-OK block."""
        diff = blocks.ModuleDiffBlock(
            modules=[
                blocks.ModuleDiffModule(
                    slot_number=0,
                    module_state=indices.MODULE_STATE_PROPER_MODULE,
                    submodules=[
                        blocks.ModuleDiffSubmodule(
                            subslot_number=1,
                            submodule_state=indices.SUBMODULE_STATE_OK,
                        ),
                    ],
                ),
            ]
        )
        assert diff.get_mismatches() == []

    def test_get_mismatches_with_wrong_module(self):
        """Test get_mismatches reports wrong module."""
        diff = blocks.ModuleDiffBlock(
            modules=[
                blocks.ModuleDiffModule(
                    slot_number=3,
                    module_state=indices.MODULE_STATE_WRONG_MODULE,
                    submodules=[
                        blocks.ModuleDiffSubmodule(
                            subslot_number=1,
                            submodule_state=indices.SUBMODULE_STATE_OK,
                        ),
                    ],
                ),
            ]
        )
        mismatches = diff.get_mismatches()
        assert len(mismatches) == 1
        assert mismatches[0] == (3, 0, "WrongModule")

    def test_get_mismatches_with_wrong_submodule(self):
        """Test get_mismatches reports wrong submodule."""
        diff = blocks.ModuleDiffBlock(
            modules=[
                blocks.ModuleDiffModule(
                    slot_number=1,
                    module_state=indices.MODULE_STATE_PROPER_MODULE,
                    submodules=[
                        blocks.ModuleDiffSubmodule(
                            subslot_number=0x8001,
                            submodule_state=indices.SUBMODULE_STATE_WRONG_SUBMODULE,
                        ),
                    ],
                ),
            ]
        )
        mismatches = diff.get_mismatches()
        assert len(mismatches) == 1
        assert mismatches[0] == (1, 0x8001, "WrongSubmodule")


class TestParseModuleDiffBlock:
    """Tests for parse_module_diff_block function."""

    def _build_module_diff_block(self, apis_data, block_type=0x8104):
        """Helper to build a ModuleDiffBlock from API data."""
        # Block header: type(2) + length(2) + version(2)
        body = struct.pack(">H", len(apis_data))  # NumberOfAPIs
        for api, modules in apis_data:
            body += struct.pack(">I", api)  # API
            body += struct.pack(">H", len(modules))  # NumberOfModules
            for slot, module_ident, module_state, submodules in modules:
                body += struct.pack(">HIHH", slot, module_ident, module_state, len(submodules))
                for subslot, submod_ident, submod_state in submodules:
                    body += struct.pack(">HIH", subslot, submod_ident, submod_state)

        block_len = len(body) + 2  # +2 for version bytes
        header = struct.pack(">HHBB", block_type, block_len, 0x01, 0x00)
        return header + body

    def test_parse_single_api_single_module(self):
        """Test parsing ModuleDiffBlock with one API and one module."""
        data = self._build_module_diff_block(
            [
                (
                    0,
                    [  # API 0
                        (
                            0,
                            0x00010001,
                            0x0002,
                            [  # Slot 0, ProperModule
                                (1, 0x00000001, 0x0007),  # Subslot 1, OK
                            ],
                        ),
                    ],
                ),
            ]
        )

        result = blocks.parse_module_diff_block(data)

        assert len(result.modules) == 1
        assert result.modules[0].api == 0
        assert result.modules[0].slot_number == 0
        assert result.modules[0].module_ident_number == 0x00010001
        assert result.modules[0].module_state == 0x0002
        assert result.modules[0].is_proper is True
        assert len(result.modules[0].submodules) == 1
        assert result.modules[0].submodules[0].subslot_number == 1
        assert result.modules[0].submodules[0].is_ok is True
        assert result.all_ok is True

    def test_parse_multiple_apis(self):
        """Test parsing ModuleDiffBlock with multiple APIs."""
        data = self._build_module_diff_block(
            [
                (
                    0,
                    [  # API 0
                        (
                            0,
                            0x00010001,
                            0x0002,
                            [
                                (1, 0x00000001, 0x0007),
                            ],
                        ),
                    ],
                ),
                (
                    1,
                    [  # API 1
                        (
                            2,
                            0x00020002,
                            0x0002,
                            [
                                (1, 0x00000002, 0x0007),
                            ],
                        ),
                    ],
                ),
            ]
        )

        result = blocks.parse_module_diff_block(data)

        assert len(result.modules) == 2
        assert result.modules[0].api == 0
        assert result.modules[1].api == 1
        assert result.modules[1].slot_number == 2

    def test_parse_wrong_block_type_raises(self):
        """Test parsing with wrong block type raises ValueError."""
        data = self._build_module_diff_block(
            [(0, [])],
            block_type=0x0400,  # Wrong type
        )

        with pytest.raises(ValueError, match="Expected block type 0x8104"):
            blocks.parse_module_diff_block(data)

    def test_parse_truncated_data(self):
        """Test parsing truncated data returns empty block."""
        result = blocks.parse_module_diff_block(b"\x81\x04\x00")
        assert len(result.modules) == 0

    def test_parse_empty_data(self):
        """Test parsing empty data returns empty block."""
        result = blocks.parse_module_diff_block(b"")
        assert len(result.modules) == 0

    def test_parse_multiple_submodules(self):
        """Test parsing module with multiple submodules."""
        data = self._build_module_diff_block(
            [
                (
                    0,
                    [
                        (
                            0,
                            0x00010001,
                            0x0002,
                            [
                                (0x0001, 0x00000001, 0x0007),  # OK
                                (0x8000, 0x00000002, 0x0007),  # OK
                                (0x8001, 0x00000003, 0x0001),  # WrongSubmodule
                            ],
                        ),
                    ],
                ),
            ]
        )

        result = blocks.parse_module_diff_block(data)

        assert len(result.modules[0].submodules) == 3
        assert result.modules[0].submodules[0].is_ok is True
        assert result.modules[0].submodules[1].is_ok is True
        assert result.modules[0].submodules[2].is_ok is False
        assert result.all_ok is False


# =============================================================================
# WriteMultipleResult Tests
# =============================================================================


class TestWriteMultipleResult:
    """Tests for WriteMultipleResult data class."""

    def test_success_property(self):
        """Test success property returns True when status is 0."""
        result = blocks.WriteMultipleResult(status=0)
        assert result.success is True

    def test_failure_property(self):
        """Test success property returns False when status is non-zero."""
        result = blocks.WriteMultipleResult(status=0x0001)
        assert result.success is False

    def test_all_fields(self):
        """Test all fields are stored correctly."""
        result = blocks.WriteMultipleResult(
            seq_num=5,
            api=0,
            slot=1,
            subslot=0x8001,
            index=0xAFF0,
            status=0,
            additional_value1=0x1234,
            additional_value2=0x5678,
        )
        assert result.seq_num == 5
        assert result.api == 0
        assert result.slot == 1
        assert result.subslot == 0x8001
        assert result.index == 0xAFF0
        assert result.additional_value1 == 0x1234
        assert result.additional_value2 == 0x5678


class TestParseWriteMultipleResponse:
    """Tests for parse_write_multiple_response function."""

    def test_parse_empty_data(self):
        """Test parsing data shorter than minimum returns empty list."""
        assert blocks.parse_write_multiple_response(b"") == []
        assert blocks.parse_write_multiple_response(b"\x00" * 32) == []

    def test_parse_single_result(self):
        """Test parsing response with single write result."""
        # Build a minimal IODWriteMultipleRes header (64 bytes)
        # followed by a single IODWriteRes block (0x8008)
        header = bytearray(64)
        # record_data_length at offset 36 (4 bytes)
        record_len = 56  # One block
        struct.pack_into(">I", header, 36, record_len)

        # Build IODWriteRes block (0x8008)
        block = bytearray(56)
        struct.pack_into(">HH", block, 0, 0x8008, 52)  # block_type, block_len
        struct.pack_into(">H", block, 6, 0)  # seq_num
        struct.pack_into(">I", block, 24, 0)  # api
        struct.pack_into(">H", block, 28, 1)  # slot
        struct.pack_into(">H", block, 30, 1)  # subslot
        struct.pack_into(">H", block, 34, 0xAFF1)  # index
        struct.pack_into(">H", block, 40, 0)  # additional_value1
        struct.pack_into(">H", block, 42, 0)  # additional_value2
        struct.pack_into(">I", block, 44, 0)  # status (success)

        data = bytes(header) + bytes(block)
        results = blocks.parse_write_multiple_response(data)

        assert len(results) == 1
        assert results[0].slot == 1
        assert results[0].subslot == 1
        assert results[0].index == 0xAFF1
        assert results[0].success is True


# =============================================================================
# IODWriteMultipleBuilder Tests
# =============================================================================


class TestIODWriteMultipleBuilder:
    """Tests for IODWriteMultipleBuilder class."""

    def test_builder_constants(self):
        """Test builder class constants."""
        assert blocks.IODWriteMultipleBuilder.INDEX == 0xE040
        assert blocks.IODWriteMultipleBuilder.BLOCK_TYPE == 0x0008

    def test_add_write_returns_self(self):
        """Test add_write returns self for chaining."""
        ar_uuid = b"\x00" * 16
        builder = blocks.IODWriteMultipleBuilder(ar_uuid)
        result = builder.add_write(0, 1, 0xAFF1, b"\x01\x02\x03")
        assert result is builder

    def test_build_single_write(self):
        """Test building with single write operation."""
        ar_uuid = b"\xaa" * 16
        builder = blocks.IODWriteMultipleBuilder(ar_uuid)
        builder.add_write(0, 1, 0xAFF1, b"\x01\x02\x03")

        data = builder.build()

        # Should produce outer header + inner block
        assert len(data) > 64
        # Outer header should have block type 0x0008
        block_type = struct.unpack_from(">H", data, 0)[0]
        assert block_type == 0x0008

    def test_build_multiple_writes(self):
        """Test building with multiple write operations."""
        ar_uuid = b"\xbb" * 16
        builder = blocks.IODWriteMultipleBuilder(ar_uuid)
        builder.add_write(0, 1, 0xAFF1, b"\x01\x02")
        builder.add_write(0, 1, 0xAFF2, b"\x03\x04")

        data = builder.build()

        # Should be larger than single write
        assert len(data) > 128

    def test_build_empty(self):
        """Test building with no writes produces header only."""
        ar_uuid = b"\x00" * 16
        builder = blocks.IODWriteMultipleBuilder(ar_uuid)
        data = builder.build()
        # Should have outer header (64 bytes: 6 block_header + 58 body)
        assert len(data) == 64

    def test_chained_writes(self):
        """Test chained add_write calls."""
        ar_uuid = b"\x00" * 16
        builder = blocks.IODWriteMultipleBuilder(ar_uuid)
        builder.add_write(0, 1, 0xAFF1, b"\x01").add_write(0, 1, 0xAFF2, b"\x02")
        assert len(builder.writes) == 2


# =============================================================================
# ExpectedSubmodule Tests
# =============================================================================


class TestExpectedSubmoduleDataDescription:
    """Tests for ExpectedSubmoduleDataDescription."""

    def test_to_bytes(self):
        """Test serialization to bytes."""
        dd = blocks.ExpectedSubmoduleDataDescription(
            data_description=1,
            submodule_data_length=10,
            length_iocs=1,
            length_iops=1,
        )
        data = dd.to_bytes()
        assert len(data) == 6  # H(2) + H(2) + B(1) + B(1)
        desc, length, iocs, iops = struct.unpack(">HHBB", data)
        assert desc == 1
        assert length == 10
        assert iocs == 1
        assert iops == 1


class TestExpectedSubmodule:
    """Tests for ExpectedSubmodule."""

    def test_submodule_type_no_io(self):
        """Test submodule type extraction for NO_IO."""
        sm = blocks.ExpectedSubmodule(submodule_properties=0x0000)
        assert sm.submodule_type == 0

    def test_submodule_type_input(self):
        """Test submodule type extraction for INPUT."""
        sm = blocks.ExpectedSubmodule(submodule_properties=0x0001)
        assert sm.submodule_type == 1

    def test_submodule_type_output(self):
        """Test submodule type extraction for OUTPUT."""
        sm = blocks.ExpectedSubmodule(submodule_properties=0x0002)
        assert sm.submodule_type == 2

    def test_submodule_type_input_output(self):
        """Test submodule type extraction for INPUT_OUTPUT."""
        sm = blocks.ExpectedSubmodule(submodule_properties=0x0003)
        assert sm.submodule_type == 3

    def test_submodule_type_masked(self):
        """Test submodule type only uses bottom 2 bits."""
        sm = blocks.ExpectedSubmodule(submodule_properties=0xFF01)
        assert sm.submodule_type == 1

    def test_to_bytes_with_data_descriptions(self):
        """Test serialization with data descriptions."""
        dd = blocks.ExpectedSubmoduleDataDescription(1, 5, 1, 1)
        sm = blocks.ExpectedSubmodule(
            subslot_number=1,
            submodule_ident_number=0x00000001,
            submodule_properties=0x0001,
            data_descriptions=[dd],
        )
        data = sm.to_bytes()
        # H(2) + I(4) + H(2) + DD(6) = 14 (no NumberOfDataDescriptions field)
        assert len(data) == 14

    def test_to_bytes_no_io_with_data_description(self):
        """Test NO_IO submodule has 1 DataDescription (per p-net reference).

        Even for NO_IO, the device expects exactly 1 Input DataDescription
        with submodule_data_length=0.
        """
        dd = blocks.ExpectedSubmoduleDataDescription(1, 0, 1, 1)
        sm = blocks.ExpectedSubmodule(
            subslot_number=1,
            submodule_ident_number=0x00000001,
            submodule_properties=0x0000,  # NO_IO
            data_descriptions=[dd],
        )
        data = sm.to_bytes()
        # H(2) + I(4) + H(2) + DD(6) = 14
        assert len(data) == 14


class TestExpectedSubmoduleAPI:
    """Tests for ExpectedSubmoduleAPI."""

    def test_to_bytes(self):
        """Test serialization to bytes."""
        api = blocks.ExpectedSubmoduleAPI(
            api=0,
            slot_number=0,
            module_ident_number=0x00010001,
            module_properties=0,
            submodules=[],
        )
        data = api.to_bytes()
        # I(4) + H(2) + I(4) + H(2) + H(2) = 14
        assert len(data) == 14


class TestExpectedSubmoduleBlockReq:
    """Tests for ExpectedSubmoduleBlockReq builder."""

    def test_block_type_constant(self):
        """Test block type is 0x0104."""
        assert blocks.ExpectedSubmoduleBlockReq.BLOCK_TYPE == 0x0104

    def test_add_submodule_no_io(self):
        """Test adding NO_IO submodule has 1 Input DataDescription with data_length=0.

        Per p-net reference, the device always reads at least 1 DataDescription
        even for NO_IO submodules.
        """
        builder = blocks.ExpectedSubmoduleBlockReq()
        builder.add_submodule(0, 0, 1, 0x00010001, 0x00000001, submodule_type=0)
        assert len(builder.apis) == 1
        assert len(builder.apis[0].submodules) == 1
        assert len(builder.apis[0].submodules[0].data_descriptions) == 1
        dd = builder.apis[0].submodules[0].data_descriptions[0]
        assert dd.data_description == 1  # Input
        assert dd.submodule_data_length == 0  # No data for NO_IO

    def test_add_submodule_input(self):
        """Test adding INPUT submodule creates input data description."""
        builder = blocks.ExpectedSubmoduleBlockReq()
        builder.add_submodule(0, 0, 1, 0x00010001, 0x00000001, submodule_type=1, input_length=10)
        sm = builder.apis[0].submodules[0]
        assert len(sm.data_descriptions) == 1
        assert sm.data_descriptions[0].data_description == 1  # Input

    def test_add_submodule_output(self):
        """Test adding OUTPUT submodule creates output data description."""
        builder = blocks.ExpectedSubmoduleBlockReq()
        builder.add_submodule(0, 0, 1, 0x00010001, 0x00000001, submodule_type=2, output_length=8)
        sm = builder.apis[0].submodules[0]
        assert len(sm.data_descriptions) == 1
        assert sm.data_descriptions[0].data_description == 2  # Output

    def test_add_submodule_input_output(self):
        """Test adding INPUT_OUTPUT submodule creates both data descriptions."""
        builder = blocks.ExpectedSubmoduleBlockReq()
        builder.add_submodule(
            0, 0, 1, 0x00010001, 0x00000001, submodule_type=3, input_length=10, output_length=8
        )
        sm = builder.apis[0].submodules[0]
        assert len(sm.data_descriptions) == 2

    def test_add_same_api_slot(self):
        """Test adding submodules to same API/slot reuses entry."""
        builder = blocks.ExpectedSubmoduleBlockReq()
        builder.add_submodule(0, 0, 1, 0x00010001, 0x00000001, submodule_type=0)
        builder.add_submodule(0, 0, 0x8000, 0x00010001, 0x00000002, submodule_type=0)
        assert len(builder.apis) == 1
        assert len(builder.apis[0].submodules) == 2

    def test_add_different_slot(self):
        """Test adding submodules to different slots creates separate entries."""
        builder = blocks.ExpectedSubmoduleBlockReq()
        builder.add_submodule(0, 0, 1, 0x00010001, 0x00000001, submodule_type=0)
        builder.add_submodule(0, 1, 1, 0x00020002, 0x00000001, submodule_type=0)
        assert len(builder.apis) == 2

    def test_to_bytes_produces_valid_header(self):
        """Test to_bytes produces block with correct header."""
        builder = blocks.ExpectedSubmoduleBlockReq()
        builder.add_submodule(0, 0, 1, 0x00010001, 0x00000001, submodule_type=0)
        data = builder.to_bytes()

        # Parse block header
        block_type, block_len, ver_hi, ver_lo = struct.unpack_from(">HHBB", data, 0)
        assert block_type == 0x0104
        assert ver_hi == 1
        assert ver_lo == 0

    def test_chained_add_submodule(self):
        """Test add_submodule returns self for chaining."""
        builder = blocks.ExpectedSubmoduleBlockReq()
        result = builder.add_submodule(0, 0, 1, 0x00010001, 0x00000001, submodule_type=0)
        assert result is builder


# =============================================================================
# BlockHeader edge cases
# =============================================================================


class TestBlockHeaderEdgeCases:
    """Additional edge case tests for BlockHeader."""

    def test_body_length_with_zero_block_length(self):
        """Test body_length returns 0 when block_length is 0."""
        header = blocks.BlockHeader(
            block_type=0x0400, block_length=0, version_high=1, version_low=0
        )
        assert header.body_length == 0

    def test_body_length_with_length_one(self):
        """Test body_length returns 0 when block_length is 1 (less than 2)."""
        header = blocks.BlockHeader(
            block_type=0x0400, block_length=1, version_high=1, version_low=0
        )
        assert header.body_length == 0

    def test_body_length_exactly_two(self):
        """Test body_length returns 0 when block_length is exactly 2."""
        header = blocks.BlockHeader(
            block_type=0x0400, block_length=2, version_high=1, version_low=0
        )
        assert header.body_length == 0

    def test_body_length_three(self):
        """Test body_length returns 1 when block_length is 3."""
        header = blocks.BlockHeader(
            block_type=0x0400, block_length=3, version_high=1, version_low=0
        )
        assert header.body_length == 1


class TestPortInfoProperties:
    """Tests for PortInfo property methods."""

    def test_link_state_up(self):
        """Test link_state property for up link."""
        port = blocks.PortInfo(
            slot=0,
            subslot=0x8001,
            port_id="port-001",
            mau_type=0,
            link_state_port=0,
            link_state_link=1,
            media_type=0,
        )
        assert port.link_state == "Up"

    def test_link_state_down(self):
        """Test link_state property for down link."""
        port = blocks.PortInfo(
            slot=0,
            subslot=0x8001,
            port_id="port-001",
            mau_type=0,
            link_state_port=0,
            link_state_link=2,
            media_type=0,
        )
        assert port.link_state == "Down"

    def test_link_state_unknown_value(self):
        """Test link_state property for unknown value."""
        port = blocks.PortInfo(
            slot=0,
            subslot=0x8001,
            port_id="port-001",
            mau_type=0,
            link_state_port=0,
            link_state_link=99,
            media_type=0,
        )
        assert "Unknown" in port.link_state

    def test_peer_info_mac_str(self):
        """Test PeerInfo mac_str property."""
        peer = blocks.PeerInfo(
            port_id="port-001",
            chassis_id="test",
            mac_address=b"\x00\x11\x22\x33\x44\x55",
        )
        assert peer.mac_str == "00:11:22:33:44:55"


class TestPDRealDataEdgeCases:
    """Additional edge case tests for PDRealData parsing."""

    def test_parse_truncated_block(self):
        """Test parsing data with truncated block gracefully handles errors."""
        # Build a header that claims more data than available
        data = struct.pack(">HHBB", 0x0400, 0x0100, 1, 0)  # Claims 258 bytes
        # Only provide header data
        result = blocks.parse_pd_real_data(data)
        # Should not crash, just return what it can
        assert isinstance(result, blocks.PDRealData)

    def test_parse_non_multiple_block_skipped(self):
        """Test that non-MultipleBlockHeader blocks are skipped."""
        # Build a block that is NOT MultipleBlockHeader (e.g., 0x0240)
        inner = b"\x00" * 10
        data = struct.pack(">HHBB", 0x0240, len(inner) + 2, 1, 0) + inner
        result = blocks.parse_pd_real_data(data)
        # Should have no slots since it's not a MultipleBlockHeader
        assert len(result.slots) == 0
