"""Tests for profinet.indices module."""

from profinet import indices


class TestGetBlockTypeName:
    """Test get_block_type_name function."""

    def test_known_block_types(self):
        """Test name lookup for known block types."""
        assert indices.get_block_type_name(0x0400) == "MultipleBlockHeader"
        assert indices.get_block_type_name(0x020F) == "PDPortDataReal"
        assert indices.get_block_type_name(0x0240) == "PDInterfaceDataReal"
        assert indices.get_block_type_name(0x0020) == "I&M0"
        assert indices.get_block_type_name(0x8104) == "ModuleDiffBlock"
        assert indices.get_block_type_name(0x0008) == "IODWriteReqHeader"
        assert indices.get_block_type_name(0x8008) == "IODWriteResHeader"
        assert indices.get_block_type_name(0x0101) == "ARBlockReq"
        assert indices.get_block_type_name(0x8101) == "ARBlockRes"

    def test_unknown_block_type(self):
        """Test name lookup for unknown block types returns formatted string."""
        name = indices.get_block_type_name(0xFFFF)
        assert "Unknown" in name
        assert "0xFFFF" in name

    def test_im_block_types(self):
        """Test all I&M block type names."""
        for i in range(16):
            block_type = 0x0020 + i
            name = indices.get_block_type_name(block_type)
            assert f"I&M{i}" == name


class TestGetAlarmTypeName:
    """Test get_alarm_type_name function."""

    def test_known_alarm_types(self):
        """Test name lookup for known alarm types."""
        assert indices.get_alarm_type_name(0x0001) == "Diagnosis"
        assert indices.get_alarm_type_name(0x0002) == "Process"
        assert indices.get_alarm_type_name(0x0003) == "Pull"
        assert indices.get_alarm_type_name(0x0004) == "Plug"
        assert indices.get_alarm_type_name(0x0005) == "Status"
        assert indices.get_alarm_type_name(0x000A) == "PlugWrongSubmodule"
        assert indices.get_alarm_type_name(0x000C) == "DiagnosisDisappears"
        assert indices.get_alarm_type_name(0x001F) == "PullModule"

    def test_unknown_alarm_type(self):
        """Test name lookup for unknown alarm type."""
        name = indices.get_alarm_type_name(0x0100)
        assert "Unknown" in name
        assert "0x0100" in name


class TestGetUSIName:
    """Test get_usi_name function."""

    def test_known_usi_values(self):
        """Test name lookup for known USI values."""
        assert indices.get_usi_name(0x8000) == "ChannelDiagnosis"
        assert indices.get_usi_name(0x8001) == "MultipleDiagnosis"
        assert indices.get_usi_name(0x8002) == "ExtChannelDiagnosis"
        assert indices.get_usi_name(0x8003) == "QualifiedChannelDiagnosis"
        assert indices.get_usi_name(0x8100) == "MaintenanceItem"
        assert indices.get_usi_name(0x8310) == "PE_AlarmItem"

    def test_manufacturer_specific_usi(self):
        """Test manufacturer-specific USI range (0x0000-0x7FFF)."""
        name = indices.get_usi_name(0x0001)
        assert "ManufacturerSpecific" in name

        name = indices.get_usi_name(0x7FFF)
        assert "ManufacturerSpecific" in name

    def test_profile_specific_usi(self):
        """Test profile-specific USI range (0x9000-0x9FFF)."""
        name = indices.get_usi_name(0x9000)
        assert "ProfileSpecific" in name

        name = indices.get_usi_name(0x9FFF)
        assert "ProfileSpecific" in name

    def test_reserved_usi(self):
        """Test reserved USI range returns Reserved."""
        name = indices.get_usi_name(0xA000)
        assert "Reserved" in name


class TestGetIOCRTypeName:
    """Test get_iocr_type_name function."""

    def test_known_iocr_types(self):
        """Test name lookup for known IOCR types."""
        assert indices.get_iocr_type_name(0x0001) == "InputCR"
        assert indices.get_iocr_type_name(0x0002) == "OutputCR"
        assert indices.get_iocr_type_name(0x0003) == "MulticastProviderCR"
        assert indices.get_iocr_type_name(0x0004) == "MulticastConsumerCR"

    def test_unknown_iocr_type(self):
        """Test name lookup for unknown IOCR type."""
        name = indices.get_iocr_type_name(0x0010)
        assert "Unknown" in name


class TestGetIOCRRTClassName:
    """Test get_iocr_rt_class_name function."""

    def test_known_rt_classes(self):
        """Test name lookup for known RT classes."""
        assert indices.get_iocr_rt_class_name(0x01) == "RT_CLASS_1"
        assert indices.get_iocr_rt_class_name(0x02) == "RT_CLASS_2"
        assert indices.get_iocr_rt_class_name(0x03) == "RT_CLASS_3"
        assert indices.get_iocr_rt_class_name(0x04) == "RT_CLASS_UDP"

    def test_unknown_rt_class(self):
        """Test name lookup for unknown RT class."""
        name = indices.get_iocr_rt_class_name(0xFF)
        assert "Unknown" in name


class TestGetPEModeName:
    """Test get_pe_mode_name function."""

    def test_power_off(self):
        """Test PE_PowerOff mode."""
        assert indices.get_pe_mode_name(0x00) == "PE_PowerOff"

    def test_energy_saving_modes(self):
        """Test energy saving mode range."""
        name = indices.get_pe_mode_name(0x01)
        assert "PE_EnergySavingMode" in name

        name = indices.get_pe_mode_name(0x1F)
        assert "PE_EnergySavingMode" in name

        name = indices.get_pe_mode_name(0x10)
        assert "PE_EnergySavingMode" in name

    def test_operate(self):
        """Test PE_Operate mode."""
        assert indices.get_pe_mode_name(0xF0) == "PE_Operate"

    def test_sleep_mode_wol(self):
        """Test PE_SleepModeWOL mode."""
        assert indices.get_pe_mode_name(0xFE) == "PE_SleepModeWOL"

    def test_ready_to_operate(self):
        """Test PE_ReadyToOperate mode."""
        assert indices.get_pe_mode_name(0xFF) == "PE_ReadyToOperate"

    def test_reserved_mode(self):
        """Test reserved mode values."""
        name = indices.get_pe_mode_name(0x20)
        assert "PE_Reserved" in name

        name = indices.get_pe_mode_name(0xEF)
        assert "PE_Reserved" in name


class TestGetIndexName:
    """Test get_index_name function."""

    def test_im_indices(self):
        """Test I&M index names."""
        assert indices.get_index_name(0xAFF0) == "I&M0"
        assert indices.get_index_name(0xAFF1) == "I&M1"
        assert indices.get_index_name(0xAFF5) == "I&M5"

    def test_im_indices_range_fallback(self):
        """Test I&M index range fallback for IM6-IM15."""
        # These are not in ALL_STANDARD_INDICES but fall in the 0xAFF0 range
        name = indices.get_index_name(0xAFF6)
        assert "I&M6" in name

        name = indices.get_index_name(0xAFFF)
        assert "I&M15" in name

    def test_diagnosis_indices(self):
        """Test diagnosis index names."""
        assert "DiagnosisChannel" in indices.get_index_name(0x800A)
        assert "DiagnosisAll" in indices.get_index_name(0x800B)
        assert "DeviceDiagnosis" in indices.get_index_name(0xF80C)

    def test_user_specific_range(self):
        """Test user/manufacturer-specific range (0x0000-0x7FFF)."""
        name = indices.get_index_name(0x0050)
        assert "User-specific" in name

    def test_subslot_data_range(self):
        """Test subslot data range (0x8000-0x8FFF) for unknown indices."""
        # Pick an index in subslot range that is not in ALL_STANDARD_INDICES
        name = indices.get_index_name(0x8FFF)
        assert "Subslot data" in name

    def test_slot_data_range(self):
        """Test slot data range (0xC000-0xCFFF)."""
        name = indices.get_index_name(0xC100)
        assert "Slot data" in name

    def test_ar_data_range(self):
        """Test AR data range (0xE000-0xEFFF) for unknown indices."""
        name = indices.get_index_name(0xE100)
        assert "AR data" in name

    def test_api_data_range(self):
        """Test API data range (0xF000-0xF7FF) for unknown indices."""
        name = indices.get_index_name(0xF100)
        assert "API data" in name

    def test_device_data_range(self):
        """Test device data range (0xF800-0xFBFF) for unknown indices."""
        # Pick one not in ALL_STANDARD_INDICES
        name = indices.get_index_name(0xF900)
        assert "Device data" in name

    def test_unknown_range(self):
        """Test completely unknown index range."""
        name = indices.get_index_name(0xFC00)
        assert "Unknown" in name


class TestGetScope:
    """Test get_scope function."""

    def test_user_scope(self):
        """Test user/manufacturer-specific scope."""
        assert indices.get_scope(0x0000) == "user"
        assert indices.get_scope(0x7FFF) == "user"

    def test_subslot_scope(self):
        """Test subslot scope."""
        assert indices.get_scope(0x8000) == "subslot"
        assert indices.get_scope(0x8FFF) == "subslot"

    def test_slot_scope(self):
        """Test slot scope (both 0xA000 and 0xC000 ranges)."""
        assert indices.get_scope(0xA000) == "slot"
        assert indices.get_scope(0xAFFF) == "slot"
        assert indices.get_scope(0xC000) == "slot"
        assert indices.get_scope(0xCFFF) == "slot"

    def test_ar_scope(self):
        """Test AR scope."""
        assert indices.get_scope(0xE000) == "ar"
        assert indices.get_scope(0xEFFF) == "ar"

    def test_api_scope(self):
        """Test API scope."""
        assert indices.get_scope(0xF000) == "api"
        assert indices.get_scope(0xF7FF) == "api"

    def test_device_scope(self):
        """Test device scope."""
        assert indices.get_scope(0xF800) == "device"
        assert indices.get_scope(0xFBFF) == "device"

    def test_unknown_scope(self):
        """Test unknown scope for out-of-range indices."""
        assert indices.get_scope(0xFC00) == "unknown"
        assert indices.get_scope(0xFFFF) == "unknown"


class TestModuleSubmoduleStateConstants:
    """Test module/submodule state constants."""

    def test_module_state_values(self):
        """Test module state constant values."""
        assert indices.MODULE_STATE_NO_MODULE == 0x0000
        assert indices.MODULE_STATE_WRONG_MODULE == 0x0001
        assert indices.MODULE_STATE_PROPER_MODULE == 0x0002
        assert indices.MODULE_STATE_SUBSTITUTE_MODULE == 0x0003

    def test_submodule_state_values(self):
        """Test submodule state constant values."""
        assert indices.SUBMODULE_STATE_NO_SUBMODULE == 0x0000
        assert indices.SUBMODULE_STATE_WRONG_SUBMODULE == 0x0001
        assert indices.SUBMODULE_STATE_LOCKED_BY_SUPERVISOR == 0x0002
        assert indices.SUBMODULE_STATE_APPLICATION_READY_PENDING == 0x0004
        assert indices.SUBMODULE_STATE_OK == 0x0007

    def test_module_state_names(self):
        """Test module state name lookup."""
        assert indices.MODULE_STATE_NAMES[0x0000] == "NoModule"
        assert indices.MODULE_STATE_NAMES[0x0002] == "ProperModule"

    def test_submodule_state_names(self):
        """Test submodule state name lookup."""
        assert indices.SUBMODULE_STATE_NAMES[0x0007] == "OK"
        assert indices.SUBMODULE_STATE_NAMES[0x0001] == "WrongSubmodule"


class TestIndexCategories:
    """Test index category lists."""

    def test_critical_indices_not_empty(self):
        """Test CRITICAL_INDICES is non-empty and contains expected entries."""
        assert len(indices.CRITICAL_INDICES) > 0
        # IM0 should be in critical indices
        im0_entries = [idx for idx, name in indices.CRITICAL_INDICES if idx == 0xAFF0]
        assert len(im0_entries) == 1

    def test_im_indices_count(self):
        """Test IM_INDICES contains all 16 I&M records."""
        assert len(indices.IM_INDICES) == 16

    def test_diagnosis_indices_by_scope(self):
        """Test diagnosis indices are organized by scope."""
        assert "subslot" in indices.DIAGNOSIS_INDICES
        assert "slot" in indices.DIAGNOSIS_INDICES
        assert "ar" in indices.DIAGNOSIS_INDICES
        assert "api" in indices.DIAGNOSIS_INDICES
        assert "device" in indices.DIAGNOSIS_INDICES

    def test_all_standard_indices_not_empty(self):
        """Test ALL_STANDARD_INDICES is populated."""
        assert len(indices.ALL_STANDARD_INDICES) > 20

    def test_standard_dap_subslots(self):
        """Test DAP subslot constants."""
        assert indices.SUBSLOT_DAP == 0x0001
        assert indices.SUBSLOT_INTERFACE == 0x8000
        assert indices.SUBSLOT_PORT1 == 0x8001
        assert indices.SUBSLOT_PORT2 == 0x8002


class TestControlCommandConstants:
    """Test control command constants."""

    def test_control_command_values(self):
        """Test control command constant values (bit fields per IEC 61158-6-10)."""
        assert indices.CONTROL_CMD_PRM_END == 0x0001  # BIT(0)
        assert indices.CONTROL_CMD_APPLICATION_READY == 0x0002  # BIT(1)
        assert indices.CONTROL_CMD_RELEASE == 0x0004  # BIT(2)
        assert indices.CONTROL_CMD_DONE == 0x0008  # BIT(3)
        assert indices.CONTROL_CMD_PRM_BEGIN == 0x0040  # BIT(6)
