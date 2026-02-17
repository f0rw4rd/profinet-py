"""Tests for profinet.diagnosis module."""

from profinet.diagnosis import (
    # Constants
    CHANNEL_ERROR_TYPES,
    EXT_CHANNEL_ERROR_TYPES_MAP,
    ChannelAccumulative,
    ChannelDiagnosis,
    ChannelDirection,
    # Data classes
    ChannelProperties,
    ChannelSpecifier,
    ChannelType,
    DiagnosisData,
    ExtChannelDiagnosis,
    QualifiedChannelDiagnosis,
    # Enums
    UserStructureIdentifier,
    # Decoding functions
    decode_channel_error_type,
    decode_ext_channel_error_type,
    # Parsing functions
    parse_diagnosis_block,
    parse_diagnosis_simple,
)


class TestUserStructureIdentifier:
    """Test UserStructureIdentifier enum."""

    def test_channel_diagnosis_value(self):
        """Test ChannelDiagnosis USI value."""
        assert UserStructureIdentifier.CHANNEL_DIAGNOSIS == 0x8000

    def test_ext_channel_diagnosis_value(self):
        """Test ExtChannelDiagnosis USI value."""
        assert UserStructureIdentifier.EXT_CHANNEL_DIAGNOSIS == 0x8002

    def test_qualified_channel_diagnosis_value(self):
        """Test QualifiedChannelDiagnosis USI value."""
        assert UserStructureIdentifier.QUALIFIED_CHANNEL_DIAGNOSIS == 0x8003

    def test_multiple_value(self):
        """Test Multiple USI value."""
        assert UserStructureIdentifier.MULTIPLE == 0x8001

    def test_maintenance_value(self):
        """Test Maintenance USI value."""
        assert UserStructureIdentifier.MAINTENANCE == 0x8100


class TestChannelType:
    """Test ChannelType enum."""

    def test_reserved_value(self):
        assert ChannelType.RESERVED == 0

    def test_specific_value(self):
        assert ChannelType.SPECIFIC == 1

    def test_all_value(self):
        assert ChannelType.ALL == 2

    def test_submodule_value(self):
        assert ChannelType.SUBMODULE == 3


class TestChannelDirection:
    """Test ChannelDirection enum."""

    def test_manufacturer_value(self):
        assert ChannelDirection.MANUFACTURER == 0

    def test_input_value(self):
        assert ChannelDirection.INPUT == 1

    def test_output_value(self):
        assert ChannelDirection.OUTPUT == 2

    def test_bidirectional_value(self):
        assert ChannelDirection.BIDIRECTIONAL == 3


class TestChannelAccumulative:
    """Test ChannelAccumulative enum."""

    def test_no_value(self):
        assert ChannelAccumulative.NO == 0

    def test_main_fault_value(self):
        assert ChannelAccumulative.MAIN_FAULT == 1

    def test_additional_fault_value(self):
        assert ChannelAccumulative.ADDITIONAL_FAULT == 2


class TestChannelSpecifier:
    """Test ChannelSpecifier enum."""

    def test_all_disappears_value(self):
        assert ChannelSpecifier.ALL_DISAPPEARS == 0

    def test_appears_value(self):
        assert ChannelSpecifier.APPEARS == 1

    def test_disappears_value(self):
        assert ChannelSpecifier.DISAPPEARS == 2

    def test_disappears_other_value(self):
        assert ChannelSpecifier.DISAPPEARS_OTHER == 3


class TestChannelProperties:
    """Test ChannelProperties dataclass and parsing."""

    def test_default_values(self):
        """Test default ChannelProperties values."""
        props = ChannelProperties()
        assert props.raw == 0
        assert props.channel_type == ChannelType.RESERVED
        assert props.accumulative == ChannelAccumulative.NO
        assert props.maintenance_required is False
        assert props.maintenance_demanded is False
        assert props.specifier == ChannelSpecifier.ALL_DISAPPEARS
        assert props.direction == ChannelDirection.MANUFACTURER

    def test_from_uint16_zero(self):
        """Test parsing zero value."""
        props = ChannelProperties.from_uint16(0x0000)
        assert props.raw == 0
        assert props.channel_type == ChannelType.RESERVED
        assert props.accumulative == ChannelAccumulative.NO
        assert props.maintenance_required is False
        assert props.maintenance_demanded is False
        assert props.specifier == ChannelSpecifier.ALL_DISAPPEARS
        assert props.direction == ChannelDirection.MANUFACTURER

    def test_from_uint16_channel_type(self):
        """Test parsing channel type bits (0-1)."""
        # Specific channel (bits 0-1 = 01)
        props = ChannelProperties.from_uint16(0x0001)
        assert props.channel_type == ChannelType.SPECIFIC

        # All channels (bits 0-1 = 10)
        props = ChannelProperties.from_uint16(0x0002)
        assert props.channel_type == ChannelType.ALL

        # Submodule (bits 0-1 = 11)
        props = ChannelProperties.from_uint16(0x0003)
        assert props.channel_type == ChannelType.SUBMODULE

    def test_from_uint16_accumulative(self):
        """Test parsing accumulative bits (2-4)."""
        # Main fault (bits 2-4 = 001)
        props = ChannelProperties.from_uint16(0x0004)
        assert props.accumulative == ChannelAccumulative.MAIN_FAULT

        # Additional fault (bits 2-4 = 010)
        props = ChannelProperties.from_uint16(0x0008)
        assert props.accumulative == ChannelAccumulative.ADDITIONAL_FAULT

    def test_from_uint16_maintenance_required(self):
        """Test parsing maintenance_required bit (5)."""
        props = ChannelProperties.from_uint16(0x0020)
        assert props.maintenance_required is True
        assert props.maintenance_demanded is False

    def test_from_uint16_maintenance_demanded(self):
        """Test parsing maintenance_demanded bit (6)."""
        props = ChannelProperties.from_uint16(0x0040)
        assert props.maintenance_required is False
        assert props.maintenance_demanded is True

    def test_from_uint16_both_maintenance_flags(self):
        """Test parsing both maintenance flags."""
        props = ChannelProperties.from_uint16(0x0060)
        assert props.maintenance_required is True
        assert props.maintenance_demanded is True

    def test_from_uint16_specifier(self):
        """Test parsing specifier bits (8-10)."""
        # Appears (bits 8-10 = 001)
        props = ChannelProperties.from_uint16(0x0100)
        assert props.specifier == ChannelSpecifier.APPEARS

        # Disappears (bits 8-10 = 010)
        props = ChannelProperties.from_uint16(0x0200)
        assert props.specifier == ChannelSpecifier.DISAPPEARS

    def test_from_uint16_direction(self):
        """Test parsing direction bits (11-12)."""
        # Input (bits 11-12 = 01)
        props = ChannelProperties.from_uint16(0x0800)
        assert props.direction == ChannelDirection.INPUT

        # Output (bits 11-12 = 10)
        props = ChannelProperties.from_uint16(0x1000)
        assert props.direction == ChannelDirection.OUTPUT

        # Bidirectional (bits 11-12 = 11)
        props = ChannelProperties.from_uint16(0x1800)
        assert props.direction == ChannelDirection.BIDIRECTIONAL

    def test_from_uint16_complex_value(self):
        """Test parsing complex combined value."""
        # Specific channel, main fault, maintenance required, appears, output
        # bits: 0-1=01, 2-4=001, 5=1, 8-10=001, 11-12=10
        value = 0x0001 | 0x0004 | 0x0020 | 0x0100 | 0x1000  # 0x1125
        props = ChannelProperties.from_uint16(value)
        assert props.channel_type == ChannelType.SPECIFIC
        assert props.accumulative == ChannelAccumulative.MAIN_FAULT
        assert props.maintenance_required is True
        assert props.specifier == ChannelSpecifier.APPEARS
        assert props.direction == ChannelDirection.OUTPUT


class TestChannelDiagnosis:
    """Test ChannelDiagnosis dataclass."""

    def test_default_values(self):
        """Test default ChannelDiagnosis values."""
        diag = ChannelDiagnosis()
        assert diag.api == 0
        assert diag.slot == 0
        assert diag.subslot == 0
        assert diag.channel_number == 0
        assert diag.error_type == 0
        assert diag.error_type_name == ""
        assert diag.is_submodule_level is False

    def test_is_submodule_level(self):
        """Test is_submodule_level property."""
        diag = ChannelDiagnosis(channel_number=0x8000)
        assert diag.is_submodule_level is True

        diag = ChannelDiagnosis(channel_number=0x0001)
        assert diag.is_submodule_level is False

    def test_with_values(self):
        """Test ChannelDiagnosis with values."""
        props = ChannelProperties(maintenance_required=True)
        diag = ChannelDiagnosis(
            api=0,
            slot=1,
            subslot=2,
            channel_number=3,
            channel_properties=props,
            error_type=0x0001,
            error_type_name="Short circuit",
        )
        assert diag.slot == 1
        assert diag.subslot == 2
        assert diag.channel_number == 3
        assert diag.error_type == 0x0001
        assert diag.error_type_name == "Short circuit"
        assert diag.channel_properties.maintenance_required is True


class TestExtChannelDiagnosis:
    """Test ExtChannelDiagnosis dataclass."""

    def test_default_values(self):
        """Test default ExtChannelDiagnosis values."""
        diag = ExtChannelDiagnosis()
        assert diag.ext_error_type == 0
        assert diag.ext_error_type_name == ""
        assert diag.ext_add_value == 0

    def test_inherits_channel_diagnosis(self):
        """Test ExtChannelDiagnosis inherits from ChannelDiagnosis."""
        diag = ExtChannelDiagnosis(
            slot=1,
            channel_number=2,
            error_type=0x8000,
            ext_error_type=0x8000,
        )
        assert diag.slot == 1
        assert diag.channel_number == 2
        assert diag.error_type == 0x8000
        assert diag.ext_error_type == 0x8000

    def test_with_full_values(self):
        """Test ExtChannelDiagnosis with all values."""
        diag = ExtChannelDiagnosis(
            api=0,
            slot=1,
            subslot=2,
            channel_number=3,
            error_type=0x8000,
            error_type_name="Data transmission impossible",
            ext_error_type=0x8000,
            ext_error_type_name="Link state mismatch - Loss of link",
            ext_add_value=0x12345678,
        )
        assert diag.error_type_name == "Data transmission impossible"
        assert diag.ext_error_type_name == "Link state mismatch - Loss of link"
        assert diag.ext_add_value == 0x12345678


class TestQualifiedChannelDiagnosis:
    """Test QualifiedChannelDiagnosis dataclass."""

    def test_default_values(self):
        """Test default QualifiedChannelDiagnosis values."""
        diag = QualifiedChannelDiagnosis()
        assert diag.qualifier == 0

    def test_inherits_ext_channel_diagnosis(self):
        """Test QualifiedChannelDiagnosis inherits from ExtChannelDiagnosis."""
        diag = QualifiedChannelDiagnosis(
            slot=1,
            ext_error_type=0x8000,
            qualifier=0xABCD,
        )
        assert diag.slot == 1
        assert diag.ext_error_type == 0x8000
        assert diag.qualifier == 0xABCD


class TestDiagnosisData:
    """Test DiagnosisData dataclass."""

    def test_default_values(self):
        """Test default DiagnosisData values."""
        data = DiagnosisData()
        assert data.api == 0
        assert data.slot == 0
        assert data.subslot == 0
        assert data.entries == []
        assert data.raw_data == b""
        assert data.has_errors is False
        assert data.has_maintenance_required is False
        assert data.has_maintenance_demanded is False

    def test_has_errors(self):
        """Test has_errors property."""
        data = DiagnosisData()
        assert data.has_errors is False

        data.entries.append(ChannelDiagnosis())
        assert data.has_errors is True

    def test_has_maintenance_required(self):
        """Test has_maintenance_required property."""
        data = DiagnosisData()
        data.entries.append(
            ChannelDiagnosis(channel_properties=ChannelProperties(maintenance_required=True))
        )
        assert data.has_maintenance_required is True
        assert data.has_maintenance_demanded is False

    def test_has_maintenance_demanded(self):
        """Test has_maintenance_demanded property."""
        data = DiagnosisData()
        data.entries.append(
            ChannelDiagnosis(channel_properties=ChannelProperties(maintenance_demanded=True))
        )
        assert data.has_maintenance_required is False
        assert data.has_maintenance_demanded is True

    def test_get_by_channel(self):
        """Test get_by_channel method."""
        data = DiagnosisData()
        data.entries.append(ChannelDiagnosis(channel_number=1))
        data.entries.append(ChannelDiagnosis(channel_number=2))
        data.entries.append(ChannelDiagnosis(channel_number=1))

        entries = data.get_by_channel(1)
        assert len(entries) == 2

        entries = data.get_by_channel(2)
        assert len(entries) == 1

        entries = data.get_by_channel(3)
        assert len(entries) == 0


class TestDecodeChannelErrorType:
    """Test decode_channel_error_type function."""

    def test_standard_errors(self):
        """Test decoding standard error types."""
        assert decode_channel_error_type(0x0001) == "Short circuit"
        assert decode_channel_error_type(0x0002) == "Undervoltage"
        assert decode_channel_error_type(0x0003) == "Overvoltage"
        assert decode_channel_error_type(0x0004) == "Overload"
        assert decode_channel_error_type(0x0005) == "Overtemperature"
        assert decode_channel_error_type(0x0006) == "Line break"
        assert decode_channel_error_type(0x0009) == "Error"

    def test_network_errors(self):
        """Test decoding network-level error types."""
        assert decode_channel_error_type(0x8000) == "Data transmission impossible"
        assert decode_channel_error_type(0x8001) == "Remote mismatch"
        assert decode_channel_error_type(0x8002) == "Media redundancy mismatch"
        assert decode_channel_error_type(0x8003) == "Sync mismatch"

    def test_reserved_errors(self):
        """Test decoding reserved error types."""
        result = decode_channel_error_type(0x0050)
        assert "Reserved" in result

    def test_manufacturer_specific(self):
        """Test decoding manufacturer-specific error types."""
        result = decode_channel_error_type(0x0100)
        assert "Manufacturer-specific" in result

        result = decode_channel_error_type(0x7FFF)
        assert "Manufacturer-specific" in result

    def test_profile_specific(self):
        """Test decoding profile-specific error types."""
        result = decode_channel_error_type(0x9000)
        assert "Profile-specific" in result

    def test_unknown(self):
        """Test decoding unknown error types."""
        result = decode_channel_error_type(0xFFFF)
        assert "Reserved" in result


class TestDecodeExtChannelErrorType:
    """Test decode_ext_channel_error_type function."""

    def test_data_transmission_impossible(self):
        """Test ExtChannelErrorType for ChannelErrorType 0x8000."""
        # Loss of link
        result = decode_ext_channel_error_type(0x8000, 0x8000)
        assert "Loss of link" in result

        # MAUType mismatch
        result = decode_ext_channel_error_type(0x8000, 0x8001)
        assert "MAUType mismatch" in result

        # Line delay mismatch
        result = decode_ext_channel_error_type(0x8000, 0x8002)
        assert "Line delay mismatch" in result

    def test_remote_mismatch(self):
        """Test ExtChannelErrorType for ChannelErrorType 0x8001."""
        result = decode_ext_channel_error_type(0x8001, 0x8000)
        assert "Peer name of station mismatch" in result

        result = decode_ext_channel_error_type(0x8001, 0x8005)
        assert "No peer detected" in result

    def test_media_redundancy_mismatch(self):
        """Test ExtChannelErrorType for ChannelErrorType 0x8002."""
        result = decode_ext_channel_error_type(0x8002, 0x8000)
        assert "Manager role fail" in result

        result = decode_ext_channel_error_type(0x8002, 0x8003)
        assert "MRP ring open" in result

    def test_sync_mismatch(self):
        """Test ExtChannelErrorType for ChannelErrorType 0x8003."""
        result = decode_ext_channel_error_type(0x8003, 0x8000)
        assert "No sync message received" in result

    def test_manufacturer_specific(self):
        """Test manufacturer-specific ExtChannelErrorType."""
        result = decode_ext_channel_error_type(0x8000, 0x0100)
        assert "Manufacturer-specific" in result

    def test_accumulative_info(self):
        """Test accumulative info ExtChannelErrorType."""
        result = decode_ext_channel_error_type(0x0001, 0x8000)
        assert "Accumulative info" in result


class TestChannelErrorTypesConstant:
    """Test CHANNEL_ERROR_TYPES constant."""

    def test_contains_basic_errors(self):
        """Test that basic errors are defined."""
        assert 0x0001 in CHANNEL_ERROR_TYPES
        assert 0x0006 in CHANNEL_ERROR_TYPES
        assert 0x0010 in CHANNEL_ERROR_TYPES

    def test_contains_network_errors(self):
        """Test that network errors are defined."""
        assert 0x8000 in CHANNEL_ERROR_TYPES
        assert 0x8001 in CHANNEL_ERROR_TYPES
        assert 0x8002 in CHANNEL_ERROR_TYPES


class TestExtChannelErrorTypesMap:
    """Test EXT_CHANNEL_ERROR_TYPES_MAP constant."""

    def test_contains_data_transmission_impossible(self):
        """Test mapping for ChannelErrorType 0x8000."""
        assert 0x8000 in EXT_CHANNEL_ERROR_TYPES_MAP
        assert 0x8000 in EXT_CHANNEL_ERROR_TYPES_MAP[0x8000]

    def test_contains_remote_mismatch(self):
        """Test mapping for ChannelErrorType 0x8001."""
        assert 0x8001 in EXT_CHANNEL_ERROR_TYPES_MAP
        assert 0x8005 in EXT_CHANNEL_ERROR_TYPES_MAP[0x8001]

    def test_contains_media_redundancy(self):
        """Test mapping for ChannelErrorType 0x8002."""
        assert 0x8002 in EXT_CHANNEL_ERROR_TYPES_MAP


class TestParseDiagnosisBlock:
    """Test parse_diagnosis_block function."""

    def test_empty_data(self):
        """Test parsing empty data."""
        result = parse_diagnosis_block(b"")
        assert result.entries == []

    def test_too_short_data(self):
        """Test parsing data shorter than header."""
        result = parse_diagnosis_block(b"\x00\x01\x02")
        assert result.entries == []

    def test_stores_raw_data(self):
        """Test that raw data is stored."""
        data = b"\x00\x01\x02\x03\x04\x05"
        result = parse_diagnosis_block(data)
        assert result.raw_data == data

    def test_api_slot_subslot_preserved(self):
        """Test that api/slot/subslot are preserved."""
        result = parse_diagnosis_block(b"\x00" * 10, api=1, slot=2, subslot=3)
        assert result.api == 1
        assert result.slot == 2
        assert result.subslot == 3

    def test_parse_channel_diagnosis(self):
        """Test parsing ChannelDiagnosis (USI 0x8000)."""
        # BlockHeader(6) + ChannelNumber(2) + ChannelProperties(2) + USI(2) + ChannelErrorType(2)
        data = (
            b"\x00\x10\x00\x08\x01\x00"  # Block header (type=0x0010, len=8, ver=1.0)
            b"\x00\x01"  # ChannelNumber = 1
            b"\x00\x00"  # ChannelProperties = 0
            b"\x80\x00"  # USI = 0x8000 (ChannelDiagnosis)
            b"\x00\x01"  # ChannelErrorType = 0x0001 (Short circuit)
        )
        result = parse_diagnosis_block(data)
        assert len(result.entries) == 1
        assert result.entries[0].channel_number == 1
        assert result.entries[0].error_type == 0x0001
        assert result.entries[0].error_type_name == "Short circuit"

    def test_parse_ext_channel_diagnosis(self):
        """Test parsing ExtChannelDiagnosis (USI 0x8002)."""
        # BlockHeader(6) + ChannelNumber(2) + ChannelProperties(2) + USI(2)
        # + ChannelErrorType(2) + ExtChannelErrorType(2) + ExtChannelAddValue(4)
        data = (
            b"\x00\x10\x00\x10\x01\x00"  # Block header
            b"\x00\x02"  # ChannelNumber = 2
            b"\x00\x20"  # ChannelProperties (maintenance_required=True)
            b"\x80\x02"  # USI = 0x8002 (ExtChannelDiagnosis)
            b"\x80\x00"  # ChannelErrorType = 0x8000 (Data transmission impossible)
            b"\x80\x00"  # ExtChannelErrorType = 0x8000 (Loss of link)
            b"\x12\x34\x56\x78"  # ExtChannelAddValue
        )
        result = parse_diagnosis_block(data)
        assert len(result.entries) == 1

        entry = result.entries[0]
        assert isinstance(entry, ExtChannelDiagnosis)
        assert entry.channel_number == 2
        assert entry.channel_properties.maintenance_required is True
        assert entry.error_type == 0x8000
        assert entry.ext_error_type == 0x8000
        assert entry.ext_add_value == 0x12345678

    def test_parse_qualified_channel_diagnosis(self):
        """Test parsing QualifiedChannelDiagnosis (USI 0x8003)."""
        # BlockHeader(6) + ChannelNumber(2) + ChannelProperties(2) + USI(2)
        # + ChannelErrorType(2) + ExtChannelErrorType(2) + ExtChannelAddValue(4) + Qualifier(4)
        data = (
            b"\x00\x10\x00\x14\x01\x00"  # Block header
            b"\x00\x03"  # ChannelNumber = 3
            b"\x00\x00"  # ChannelProperties
            b"\x80\x03"  # USI = 0x8003 (QualifiedChannelDiagnosis)
            b"\x80\x01"  # ChannelErrorType = 0x8001 (Remote mismatch)
            b"\x80\x05"  # ExtChannelErrorType = 0x8005 (No peer detected)
            b"\x00\x00\x00\x01"  # ExtChannelAddValue
            b"\xab\xcd\xef\x01"  # Qualifier
        )
        result = parse_diagnosis_block(data)
        assert len(result.entries) == 1

        entry = result.entries[0]
        assert isinstance(entry, QualifiedChannelDiagnosis)
        assert entry.channel_number == 3
        assert entry.error_type == 0x8001
        assert entry.ext_error_type == 0x8005
        assert entry.qualifier == 0xABCDEF01


class TestParseDiagnosisSimple:
    """Test parse_diagnosis_simple function."""

    def test_empty_data(self):
        """Test parsing empty data."""
        result = parse_diagnosis_simple(b"")
        assert result.entries == []

    def test_too_short_data(self):
        """Test parsing data shorter than header."""
        result = parse_diagnosis_simple(b"\x00\x01\x02")
        assert result.entries == []

    def test_parse_simple_entry(self):
        """Test parsing simple diagnosis entry format."""
        # BlockHeader(6) + ChannelNumber(2) + ChannelProperties(2) + ChannelErrorType(2)
        data = (
            b"\x00\x10\x00\x06\x01\x00"  # Block header
            b"\x00\x01"  # ChannelNumber = 1
            b"\x00\x00"  # ChannelProperties
            b"\x00\x06"  # ChannelErrorType = 0x0006 (Line break)
        )
        result = parse_diagnosis_simple(data)
        assert len(result.entries) == 1
        assert result.entries[0].channel_number == 1
        assert result.entries[0].error_type == 0x0006
        assert result.entries[0].error_type_name == "Line break"

    def test_parse_multiple_entries(self):
        """Test parsing multiple simple entries."""
        data = (
            b"\x00\x10\x00\x0c\x01\x00"  # Block header
            b"\x00\x01"  # ChannelNumber = 1
            b"\x00\x00"  # ChannelProperties
            b"\x00\x01"  # ChannelErrorType = Short circuit
            b"\x00\x02"  # ChannelNumber = 2
            b"\x00\x20"  # ChannelProperties (maintenance_required)
            b"\x00\x06"  # ChannelErrorType = Line break
        )
        result = parse_diagnosis_simple(data)
        assert len(result.entries) == 2
        assert result.entries[0].channel_number == 1
        assert result.entries[0].error_type == 0x0001
        assert result.entries[1].channel_number == 2
        assert result.entries[1].error_type == 0x0006
        assert result.entries[1].channel_properties.maintenance_required is True

    def test_stops_at_zero_entry(self):
        """Test that parsing stops at all-zero entry."""
        data = (
            b"\x00\x10\x00\x12\x01\x00"  # Block header
            b"\x00\x01"  # ChannelNumber = 1
            b"\x00\x00"  # ChannelProperties
            b"\x00\x01"  # ChannelErrorType
            b"\x00\x00"  # ChannelNumber = 0
            b"\x00\x00"  # ChannelProperties = 0
            b"\x00\x00"  # ChannelErrorType = 0 (should stop here)
            b"\x00\x02"  # This should not be parsed
            b"\x00\x00"
            b"\x00\x06"
        )
        result = parse_diagnosis_simple(data)
        assert len(result.entries) == 1


class TestImportsFromModule:
    """Test that all exports are importable from main module."""

    def test_import_from_profinet(self):
        """Test importing diagnosis from profinet package."""
        from profinet import (
            ChannelDiagnosis,
            DiagnosisData,
            parse_diagnosis_block,
        )

        # Just verify they're importable
        assert DiagnosisData is not None
        assert ChannelDiagnosis is not None
        assert parse_diagnosis_block is not None
