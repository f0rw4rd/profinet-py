"""
PROFINET IO Record Data Index definitions.

Provides constants for all standardized PROFINET indices organized by category.
Index ranges determine addressing scope:
- 0x0000-0x7FFF: User/manufacturer specific
- 0x8000-0x8FFF: Subslot level
- 0xA000-0xAFFF: I&M data (slot level)
- 0xC000-0xCFFF: Slot level
- 0xE000-0xEFFF: AR (Application Relationship) level
- 0xF000-0xF7FF: API level
- 0xF800-0xFBFF: Device level
"""

from typing import Dict, List, Tuple

# =============================================================================
# Block Types (from Wireshark pn_io_block_type dissector)
# Used in block headers to identify block content
# =============================================================================

# Diagnosis blocks
BLOCK_DIAGNOSIS_DATA = 0x0010
BLOCK_EXPECTED_IDENTIFICATION_DATA = 0x0012
BLOCK_REAL_IDENTIFICATION_DATA = 0x0013

# I&M blocks
BLOCK_IM0 = 0x0020
BLOCK_IM1 = 0x0021
BLOCK_IM2 = 0x0022
BLOCK_IM3 = 0x0023
BLOCK_IM4 = 0x0024
BLOCK_IM5 = 0x0025
BLOCK_IM6 = 0x0026
BLOCK_IM7 = 0x0027
BLOCK_IM8 = 0x0028
BLOCK_IM9 = 0x0029
BLOCK_IM10 = 0x002A
BLOCK_IM11 = 0x002B
BLOCK_IM12 = 0x002C
BLOCK_IM13 = 0x002D
BLOCK_IM14 = 0x002E
BLOCK_IM15 = 0x002F

# Alarm blocks
BLOCK_ALARM_NOTIFICATION_HIGH = 0x0001
BLOCK_ALARM_ACK_HIGH = 0x8001
BLOCK_ALARM_NOTIFICATION_LOW = 0x0002
BLOCK_ALARM_ACK_LOW = 0x8002

# IOD Read/Write blocks
BLOCK_IOD_WRITE_REQ = 0x0008
BLOCK_IOD_WRITE_RES = 0x8008
BLOCK_IOD_READ_REQ = 0x0009
BLOCK_IOD_READ_RES = 0x8009

# AR data blocks
BLOCK_AR_DATA = 0x0018
BLOCK_LOG_DATA = 0x0019
BLOCK_API_DATA = 0x001A
BLOCK_SRL_DATA = 0x001B

# AR/IOCR/AlarmCR connection blocks
BLOCK_AR_REQ = 0x0101
BLOCK_AR_RES = 0x8101
BLOCK_IOCR_REQ = 0x0102
BLOCK_IOCR_RES = 0x8102
BLOCK_ALARM_CR_REQ = 0x0103
BLOCK_ALARM_CR_RES = 0x8103
BLOCK_EXPECTED_SUBMODULE_REQ = 0x0104
BLOCK_MODULE_DIFF_BLOCK = 0x8104

# Control operation blocks
BLOCK_IOD_CONTROL_PRM_END_REQ = 0x0110
BLOCK_IOD_CONTROL_PRM_END_RES = 0x8110
BLOCK_IOD_CONTROL_APP_READY_REQ = 0x0112
BLOCK_IOD_CONTROL_APP_READY_RES = 0x8112
BLOCK_IOD_RELEASE_REQ = 0x0114
BLOCK_IOD_RELEASE_RES = 0x8114
BLOCK_IOD_CONTROL_RT_CLASS_3_REQ = 0x0117
BLOCK_IOD_CONTROL_RT_CLASS_3_RES = 0x8117
BLOCK_PRM_BEGIN_REQ = 0x0118
BLOCK_PRM_BEGIN_RES = 0x8118
BLOCK_SUBMODULE_LIST = 0x0119  # SubmoduleListBlock (appended to ApplicationReady)

# Control command values (bit field, each is BIT(n) per IEC 61158-6-10)
CONTROL_CMD_PRM_END = 0x0001  # BIT(0): End parameter phase
CONTROL_CMD_APPLICATION_READY = 0x0002  # BIT(1): Signal application ready
CONTROL_CMD_RELEASE = 0x0004  # BIT(2): Release AR
CONTROL_CMD_DONE = 0x0008  # BIT(3): Confirm/Done (used in CControl response)
CONTROL_CMD_READY_FOR_COMPANION = 0x0010  # BIT(4): Ready for companion AR
CONTROL_CMD_READY_FOR_RT_CLASS_3 = 0x0020  # BIT(5): Ready for isochronous mode
CONTROL_CMD_PRM_BEGIN = 0x0040  # BIT(6): Begin parameter phase

# Port and interface data blocks
BLOCK_PD_PORT_DATA_CHECK = 0x0200
BLOCK_PD_PORT_DATA_ADJUST = 0x0202
BLOCK_PD_PORT_DATA_REAL = 0x020F
BLOCK_PD_INTERFACE_MRP_DATA_ADJUST = 0x0211
BLOCK_PD_INTERFACE_MRP_DATA_REAL = 0x0212
BLOCK_PD_PORT_MRP_DATA_REAL = 0x0215
BLOCK_MRP_RING_STATE_DATA = 0x0219
BLOCK_PD_PORT_FO_DATA_REAL = 0x0220
BLOCK_PD_PORT_FO_DATA_CHECK = 0x0221
BLOCK_PD_PORT_FO_DATA_ADJUST = 0x0222
BLOCK_PD_PORT_DATA_REAL_EXTENDED = 0x022C
BLOCK_PD_INTERFACE_DATA_REAL = 0x0240
BLOCK_PD_PORT_STATISTIC = 0x0251

# Container blocks
BLOCK_MULTIPLE_HEADER = 0x0400
BLOCK_CO_CONTAINER_CONTENT = 0x0401

# Device-level blocks (0xF8xx)
BLOCK_AR_SERVER_BLOCK = 0xF820
BLOCK_PD_REAL_DATA = 0xF841
BLOCK_PD_EXPECTED_DATA = 0xF842

# API-level blocks (0xF0xx)
BLOCK_REAL_IDENTIFICATION_DATA_API = 0xF000

# Block type name mapping for debugging/display
BLOCK_TYPE_NAMES: Dict[int, str] = {
    BLOCK_ALARM_NOTIFICATION_HIGH: "AlarmNotificationHigh",
    BLOCK_ALARM_ACK_HIGH: "AlarmAckHigh",
    BLOCK_ALARM_NOTIFICATION_LOW: "AlarmNotificationLow",
    BLOCK_ALARM_ACK_LOW: "AlarmAckLow",
    BLOCK_IOD_WRITE_REQ: "IODWriteReqHeader",
    BLOCK_IOD_WRITE_RES: "IODWriteResHeader",
    BLOCK_IOD_READ_REQ: "IODReadReqHeader",
    BLOCK_IOD_READ_RES: "IODReadResHeader",
    BLOCK_DIAGNOSIS_DATA: "DiagnosisData",
    BLOCK_EXPECTED_IDENTIFICATION_DATA: "ExpectedIdentificationData",
    BLOCK_REAL_IDENTIFICATION_DATA: "RealIdentificationData",
    BLOCK_IM0: "I&M0",
    BLOCK_IM1: "I&M1",
    BLOCK_IM2: "I&M2",
    BLOCK_IM3: "I&M3",
    BLOCK_IM4: "I&M4",
    BLOCK_IM5: "I&M5",
    BLOCK_IM6: "I&M6",
    BLOCK_IM7: "I&M7",
    BLOCK_IM8: "I&M8",
    BLOCK_IM9: "I&M9",
    BLOCK_IM10: "I&M10",
    BLOCK_IM11: "I&M11",
    BLOCK_IM12: "I&M12",
    BLOCK_IM13: "I&M13",
    BLOCK_IM14: "I&M14",
    BLOCK_IM15: "I&M15",
    BLOCK_AR_REQ: "ARBlockReq",
    BLOCK_AR_RES: "ARBlockRes",
    BLOCK_IOCR_REQ: "IOCRBlockReq",
    BLOCK_IOCR_RES: "IOCRBlockRes",
    BLOCK_ALARM_CR_REQ: "AlarmCRBlockReq",
    BLOCK_ALARM_CR_RES: "AlarmCRBlockRes",
    BLOCK_EXPECTED_SUBMODULE_REQ: "ExpectedSubmoduleBlockReq",
    BLOCK_MODULE_DIFF_BLOCK: "ModuleDiffBlock",
    BLOCK_IOD_CONTROL_PRM_END_REQ: "IODControlReqPrmEnd",
    BLOCK_IOD_CONTROL_PRM_END_RES: "IODControlResPrmEnd",
    BLOCK_IOD_CONTROL_APP_READY_REQ: "IODControlReqAppReady",
    BLOCK_IOD_CONTROL_APP_READY_RES: "IODControlResAppReady",
    BLOCK_IOD_RELEASE_REQ: "IODReleaseReq",
    BLOCK_IOD_RELEASE_RES: "IODReleaseRes",
    BLOCK_IOD_CONTROL_RT_CLASS_3_REQ: "IODControlReqRTClass3",
    BLOCK_IOD_CONTROL_RT_CLASS_3_RES: "IODControlResRTClass3",
    BLOCK_PRM_BEGIN_REQ: "PrmBeginReq",
    BLOCK_PRM_BEGIN_RES: "PrmBeginRes",
    BLOCK_SUBMODULE_LIST: "SubmoduleListBlock",
    BLOCK_AR_DATA: "ARData",
    BLOCK_LOG_DATA: "LogData",
    BLOCK_API_DATA: "APIData",
    BLOCK_SRL_DATA: "SRLData",
    BLOCK_PD_PORT_DATA_CHECK: "PDPortDataCheck",
    BLOCK_PD_PORT_DATA_ADJUST: "PDPortDataAdjust",
    BLOCK_PD_PORT_DATA_REAL: "PDPortDataReal",
    BLOCK_PD_INTERFACE_MRP_DATA_ADJUST: "PDInterfaceMrpDataAdjust",
    BLOCK_PD_INTERFACE_MRP_DATA_REAL: "PDInterfaceMrpDataReal",
    BLOCK_PD_PORT_MRP_DATA_REAL: "PDPortMrpDataReal",
    BLOCK_MRP_RING_STATE_DATA: "MrpRingStateData",
    BLOCK_PD_PORT_FO_DATA_REAL: "PDPortFODataReal",
    BLOCK_PD_PORT_FO_DATA_CHECK: "PDPortFODataCheck",
    BLOCK_PD_PORT_FO_DATA_ADJUST: "PDPortFODataAdjust",
    BLOCK_PD_PORT_DATA_REAL_EXTENDED: "PDPortDataRealExtended",
    BLOCK_PD_INTERFACE_DATA_REAL: "PDInterfaceDataReal",
    BLOCK_PD_PORT_STATISTIC: "PDPortStatistic",
    BLOCK_MULTIPLE_HEADER: "MultipleBlockHeader",
    BLOCK_CO_CONTAINER_CONTENT: "COContainerContent",
    BLOCK_AR_SERVER_BLOCK: "ARServerBlock",
    BLOCK_PD_REAL_DATA: "PDRealData",
    BLOCK_PD_EXPECTED_DATA: "PDExpectedData",
    BLOCK_REAL_IDENTIFICATION_DATA_API: "RealIdentificationDataAPI",
}


def get_block_type_name(block_type: int) -> str:
    """Get human-readable name for a block type."""
    return BLOCK_TYPE_NAMES.get(block_type, f"Unknown(0x{block_type:04X})")


# =============================================================================
# Alarm Types (used in AlarmNotification blocks)
# =============================================================================

ALARM_TYPE_DIAGNOSIS = 0x0001
ALARM_TYPE_PROCESS = 0x0002
ALARM_TYPE_PULL = 0x0003
ALARM_TYPE_PLUG = 0x0004
ALARM_TYPE_STATUS = 0x0005
ALARM_TYPE_UPDATE = 0x0006
ALARM_TYPE_REDUNDANCY = 0x0007
ALARM_TYPE_CONTROLLED_BY_SUPERVISOR = 0x0008
ALARM_TYPE_RELEASED = 0x0009
ALARM_TYPE_PLUG_WRONG_SUBMODULE = 0x000A
ALARM_TYPE_RETURN_OF_SUBMODULE = 0x000B
ALARM_TYPE_DIAGNOSIS_DISAPPEARS = 0x000C
ALARM_TYPE_MULTICAST_MISMATCH = 0x000D
ALARM_TYPE_PORT_DATA_CHANGE = 0x000E
ALARM_TYPE_SYNC_DATA_CHANGED = 0x000F
ALARM_TYPE_ISOCHRONOUS_MODE_PROBLEM = 0x0010
ALARM_TYPE_NETWORK_COMPONENT_PROBLEM = 0x0011
ALARM_TYPE_TIME_DATA_CHANGED = 0x0012
ALARM_TYPE_DFP_PROBLEM = 0x0013
ALARM_TYPE_UPLOAD_RETRIEVAL = 0x001E
ALARM_TYPE_PULL_MODULE = 0x001F

ALARM_TYPE_NAMES: Dict[int, str] = {
    ALARM_TYPE_DIAGNOSIS: "Diagnosis",
    ALARM_TYPE_PROCESS: "Process",
    ALARM_TYPE_PULL: "Pull",
    ALARM_TYPE_PLUG: "Plug",
    ALARM_TYPE_STATUS: "Status",
    ALARM_TYPE_UPDATE: "Update",
    ALARM_TYPE_REDUNDANCY: "Redundancy",
    ALARM_TYPE_CONTROLLED_BY_SUPERVISOR: "ControlledBySupervisor",
    ALARM_TYPE_RELEASED: "Released",
    ALARM_TYPE_PLUG_WRONG_SUBMODULE: "PlugWrongSubmodule",
    ALARM_TYPE_RETURN_OF_SUBMODULE: "ReturnOfSubmodule",
    ALARM_TYPE_DIAGNOSIS_DISAPPEARS: "DiagnosisDisappears",
    ALARM_TYPE_MULTICAST_MISMATCH: "MulticastMismatch",
    ALARM_TYPE_PORT_DATA_CHANGE: "PortDataChange",
    ALARM_TYPE_SYNC_DATA_CHANGED: "SyncDataChanged",
    ALARM_TYPE_ISOCHRONOUS_MODE_PROBLEM: "IsochronousModeProblem",
    ALARM_TYPE_NETWORK_COMPONENT_PROBLEM: "NetworkComponentProblem",
    ALARM_TYPE_TIME_DATA_CHANGED: "TimeDataChanged",
    ALARM_TYPE_DFP_PROBLEM: "DynamicFramePackingProblem",
    ALARM_TYPE_UPLOAD_RETRIEVAL: "UploadAndRetrieval",
    ALARM_TYPE_PULL_MODULE: "PullModule",
}


def get_alarm_type_name(alarm_type: int) -> str:
    """Get human-readable name for an alarm type."""
    return ALARM_TYPE_NAMES.get(alarm_type, f"Unknown(0x{alarm_type:04X})")


# =============================================================================
# IOCR (IO Connection Relationship) Types and Properties
# =============================================================================

# IOCR Types - used in IOCRBlockReq/Res
IOCR_TYPE_INPUT = 0x0001  # InputCR - receive data from device
IOCR_TYPE_OUTPUT = 0x0002  # OutputCR - send data to device
IOCR_TYPE_MULTICAST_PROVIDER = 0x0003  # Multicast provider CR
IOCR_TYPE_MULTICAST_CONSUMER = 0x0004  # Multicast consumer CR

IOCR_TYPE_NAMES: Dict[int, str] = {
    IOCR_TYPE_INPUT: "InputCR",
    IOCR_TYPE_OUTPUT: "OutputCR",
    IOCR_TYPE_MULTICAST_PROVIDER: "MulticastProviderCR",
    IOCR_TYPE_MULTICAST_CONSUMER: "MulticastConsumerCR",
}

# IOCR RT Classes (bits 0-3 of IOCRProperties)
IOCR_RT_CLASS_1 = 0x01  # RT_CLASS_1 (non-IRT, software scheduling)
IOCR_RT_CLASS_2 = 0x02  # RT_CLASS_2 (reserved)
IOCR_RT_CLASS_3 = 0x03  # RT_CLASS_3 (IRT, hardware scheduling)
IOCR_RT_CLASS_UDP = 0x04  # RT_CLASS_UDP (UDP-based RT)

IOCR_RT_CLASS_NAMES: Dict[int, str] = {
    IOCR_RT_CLASS_1: "RT_CLASS_1",
    IOCR_RT_CLASS_2: "RT_CLASS_2",
    IOCR_RT_CLASS_3: "RT_CLASS_3",
    IOCR_RT_CLASS_UDP: "RT_CLASS_UDP",
}


def get_iocr_type_name(iocr_type: int) -> str:
    """Get human-readable name for an IOCR type."""
    return IOCR_TYPE_NAMES.get(iocr_type, f"Unknown(0x{iocr_type:04X})")


def get_iocr_rt_class_name(rt_class: int) -> str:
    """Get human-readable name for an IOCR RT class."""
    return IOCR_RT_CLASS_NAMES.get(rt_class, f"Unknown(0x{rt_class:02X})")


# =============================================================================
# AlarmCR (Alarm Connection Relationship) Types
# =============================================================================

ALARM_CR_TYPE_ALARM = 0x0001  # Standard alarm CR

ALARM_CR_TYPE_NAMES: Dict[int, str] = {
    ALARM_CR_TYPE_ALARM: "AlarmCR",
}

# AlarmCR Transport (bit 1 of AlarmCRProperties)
ALARM_TRANSPORT_RTA_CLASS_1 = 0x00  # RT-Acyclic Class 1 (Layer 2)
ALARM_TRANSPORT_RTA_CLASS_UDP = 0x01  # RT-Acyclic over UDP

ALARM_TRANSPORT_NAMES: Dict[int, str] = {
    ALARM_TRANSPORT_RTA_CLASS_1: "RTA_CLASS_1",
    ALARM_TRANSPORT_RTA_CLASS_UDP: "RTA_CLASS_UDP",
}


# =============================================================================
# AR (Application Relationship) Types
# =============================================================================

AR_TYPE_IOCAR_SINGLE = 0x0001  # Standard single AR
AR_TYPE_IOSAR = 0x0006  # Supervisor AR
AR_TYPE_IOCAR_SINGLE_RT_CLASS_3 = 0x0010  # Single AR with RT_CLASS_3
AR_TYPE_IOCARSR = 0x0020  # System redundancy AR

AR_TYPE_NAMES: Dict[int, str] = {
    AR_TYPE_IOCAR_SINGLE: "IOCARSingle",
    AR_TYPE_IOSAR: "IOSAR",
    AR_TYPE_IOCAR_SINGLE_RT_CLASS_3: "IOCARSingle_RT_CLASS_3",
    AR_TYPE_IOCARSR: "IOCARSR",
}


# =============================================================================
# User Structure Identifiers (USI) for Alarm Items
# =============================================================================

USI_CHANNEL_DIAGNOSIS = 0x8000  # ChannelDiagnosis
USI_MULTIPLE_DIAGNOSIS = 0x8001  # MultipleDiagnosis (list of ChannelDiagnosis)
USI_EXT_CHANNEL_DIAGNOSIS = 0x8002  # ExtChannelDiagnosis
USI_QUALIFIED_CHANNEL_DIAGNOSIS = 0x8003  # QualifiedChannelDiagnosis
USI_MAINTENANCE = 0x8100  # MaintenanceItem
USI_UPLOAD = 0x8200  # UploadRecord
USI_IPARAMETER = 0x8201  # iParameterItem
USI_RS_ALARM_LOW = 0x8300  # RS_AlarmItem (low priority)
USI_RS_ALARM_HIGH = 0x8301  # RS_AlarmItem (high priority)
USI_RS_ALARM_SUBMODULE = 0x8302  # RS_AlarmItem (submodule)
USI_PE_ALARM = 0x8310  # PE_AlarmItem (PROFIenergy)
USI_PRAL_ALARM = 0x8320  # PRAL_AlarmItem (Pull Request)

USI_NAMES: Dict[int, str] = {
    USI_CHANNEL_DIAGNOSIS: "ChannelDiagnosis",
    USI_MULTIPLE_DIAGNOSIS: "MultipleDiagnosis",
    USI_EXT_CHANNEL_DIAGNOSIS: "ExtChannelDiagnosis",
    USI_QUALIFIED_CHANNEL_DIAGNOSIS: "QualifiedChannelDiagnosis",
    USI_MAINTENANCE: "MaintenanceItem",
    USI_UPLOAD: "UploadRecord",
    USI_IPARAMETER: "iParameterItem",
    USI_RS_ALARM_LOW: "RS_AlarmItem_Low",
    USI_RS_ALARM_HIGH: "RS_AlarmItem_High",
    USI_RS_ALARM_SUBMODULE: "RS_AlarmItem_Submodule",
    USI_PE_ALARM: "PE_AlarmItem",
    USI_PRAL_ALARM: "PRAL_AlarmItem",
}


def get_usi_name(usi: int) -> str:
    """Get human-readable name for a User Structure Identifier."""
    if usi in USI_NAMES:
        return USI_NAMES[usi]
    elif 0x0000 <= usi <= 0x7FFF:
        return f"ManufacturerSpecific(0x{usi:04X})"
    elif 0x9000 <= usi <= 0x9FFF:
        return f"ProfileSpecific(0x{usi:04X})"
    else:
        return f"Reserved(0x{usi:04X})"


# =============================================================================
# Module/Submodule State Values (for ModuleDiffBlock)
# =============================================================================

# Module states
MODULE_STATE_NO_MODULE = 0x0000
MODULE_STATE_WRONG_MODULE = 0x0001
MODULE_STATE_PROPER_MODULE = 0x0002
MODULE_STATE_SUBSTITUTE_MODULE = 0x0003

# Submodule states
SUBMODULE_STATE_NO_SUBMODULE = 0x0000
SUBMODULE_STATE_WRONG_SUBMODULE = 0x0001
SUBMODULE_STATE_LOCKED_BY_SUPERVISOR = 0x0002
SUBMODULE_STATE_APPLICATION_READY_PENDING = 0x0004
SUBMODULE_STATE_OK = 0x0007

MODULE_STATE_NAMES: Dict[int, str] = {
    MODULE_STATE_NO_MODULE: "NoModule",
    MODULE_STATE_WRONG_MODULE: "WrongModule",
    MODULE_STATE_PROPER_MODULE: "ProperModule",
    MODULE_STATE_SUBSTITUTE_MODULE: "SubstituteModule",
}

SUBMODULE_STATE_NAMES: Dict[int, str] = {
    SUBMODULE_STATE_NO_SUBMODULE: "NoSubmodule",
    SUBMODULE_STATE_WRONG_SUBMODULE: "WrongSubmodule",
    SUBMODULE_STATE_LOCKED_BY_SUPERVISOR: "LockedBySupervisor",
    SUBMODULE_STATE_APPLICATION_READY_PENDING: "ApplicationReadyPending",
    SUBMODULE_STATE_OK: "OK",
}


# =============================================================================
# PROFIenergy Operational Modes
# =============================================================================

PE_MODE_POWER_OFF = 0x00
PE_MODE_ENERGY_SAVING_MIN = 0x01  # 0x01-0x1F are energy saving modes
PE_MODE_ENERGY_SAVING_MAX = 0x1F
PE_MODE_OPERATE = 0xF0
PE_MODE_SLEEP_MODE_WOL = 0xFE
PE_MODE_READY_TO_OPERATE = 0xFF


def get_pe_mode_name(mode: int) -> str:
    """Get human-readable name for a PROFIenergy mode."""
    if mode == PE_MODE_POWER_OFF:
        return "PE_PowerOff"
    elif PE_MODE_ENERGY_SAVING_MIN <= mode <= PE_MODE_ENERGY_SAVING_MAX:
        return f"PE_EnergySavingMode_{mode}"
    elif mode == PE_MODE_OPERATE:
        return "PE_Operate"
    elif mode == PE_MODE_SLEEP_MODE_WOL:
        return "PE_SleepModeWOL"
    elif mode == PE_MODE_READY_TO_OPERATE:
        return "PE_ReadyToOperate"
    else:
        return f"PE_Reserved(0x{mode:02X})"


# =============================================================================
# I&M (Identification & Maintenance) Indices - 0xAFFx
# =============================================================================

IM0 = 0xAFF0  # Mandatory: VendorID, OrderID, SerialNumber, HW/SW revision
IM1 = 0xAFF1  # Tag_Function + Tag_Location
IM2 = 0xAFF2  # Installation_Date
IM3 = 0xAFF3  # Descriptor
IM4 = 0xAFF4  # Safety signature (PROFIsafe)
IM5 = 0xAFF5  # Annotation string
IM6 = 0xAFF6  # Reserved for future use
IM7 = 0xAFF7  # Reserved for future use
IM8 = 0xAFF8  # Reserved for future use
IM9 = 0xAFF9  # Reserved for future use
IM10 = 0xAFFA  # Reserved for future use
IM11 = 0xAFFB  # Reserved for future use
IM12 = 0xAFFC  # Reserved for future use
IM13 = 0xAFFD  # Reserved for future use
IM14 = 0xAFFE  # Reserved for future use
IM15 = 0xAFFF  # Reserved for future use
IM0_FILTER_DATA = 0xF840  # Lists all submodules with I&M data

# =============================================================================
# Diagnosis Indices - Pattern: 0x__0A/B/C
# =============================================================================

# Subslot level (0x800x)
DIAG_CHANNEL_SUBSLOT = 0x800A
DIAG_ALL_SUBSLOT = 0x800B
DIAG_MAINTENANCE_SUBSLOT = 0x800C

# Slot level (0xC00x)
DIAG_CHANNEL_SLOT = 0xC00A
DIAG_ALL_SLOT = 0xC00B
DIAG_MAINTENANCE_SLOT = 0xC00C

# AR level (0xE00x)
DIAG_CHANNEL_AR = 0xE00A
DIAG_ALL_AR = 0xE00B
DIAG_MAINTENANCE_AR = 0xE00C

# API level (0xF00x)
DIAG_CHANNEL_API = 0xF00A
DIAG_ALL_API = 0xF00B
DIAG_MAINTENANCE_API = 0xF00C

# Device level
DIAG_DEVICE = 0xF80C  # All diagnosis for entire device

# =============================================================================
# Maintenance Indices - Pattern: 0x__10-13
# =============================================================================

MAINT_REQUIRED_CHANNEL_SUBSLOT = 0x8010
MAINT_DEMANDED_CHANNEL_SUBSLOT = 0x8011
MAINT_REQUIRED_ALL_SUBSLOT = 0x8012
MAINT_DEMANDED_ALL_SUBSLOT = 0x8013

# =============================================================================
# Configuration/Identification Indices
# =============================================================================

# Subslot level
EXPECTED_ID_SUBSLOT = 0x8000
REAL_ID_SUBSLOT = 0x8001

# AR level
EXPECTED_ID_AR = 0xE000
REAL_ID_AR = 0xE001
MODULE_DIFF_BLOCK = 0xE002  # Deviation between expected and real

# API level
REAL_ID_API = 0xF000

# Device level
AR_DATA = 0xF820
API_DATA = 0xF821
PDEV_DATA = 0xF831
PD_REAL_DATA = 0xF841
PD_EXPECTED_DATA = 0xF842
AUTO_CONFIG = 0xF850
LOG_DATA = 0xF830

# =============================================================================
# PDPort Indices (for port subslots 0x8001, 0x8002, etc.)
# =============================================================================

PD_PORT_DATA_REAL = 0x802A
PD_PORT_DATA_CHECK = 0x802B
PD_IR_DATA = 0x802C
PD_SYNC_DATA = 0x802D
PD_PORT_DATA_ADJUST = 0x802F
PD_PORT_STATISTIC = 0x8072

# =============================================================================
# PDInterface Indices (for interface subslot 0x8000)
# =============================================================================

PD_NC_DATA_CHECK = 0x8070
PD_INTERFACE_ADJUST = 0x8071
PD_INTERFACE_DATA_REAL = 0x8080
PD_INTERFACE_FSU_ADJUST = 0x8090

# =============================================================================
# Fiber Optic Indices
# =============================================================================

PD_PORT_FO_DATA_REAL = 0x8060
PD_PORT_FO_DATA_CHECK = 0x8061
PD_PORT_FO_DATA_ADJUST = 0x8062
PD_PORT_SFP_DATA_CHECK = 0x8063

# =============================================================================
# MRP (Media Redundancy Protocol) Indices
# =============================================================================

# Interface level (subslot 0x8000)
PD_INTERFACE_MRP_DATA_REAL = 0x8050
PD_INTERFACE_MRP_DATA_CHECK = 0x8051
PD_INTERFACE_MRP_DATA_ADJUST = 0x8052

# Port level
PD_PORT_MRP_DATA_ADJUST = 0x8053
PD_PORT_MRP_DATA_REAL = 0x8054
PD_PORT_MRP_IC_DATA_ADJUST = 0x8055
PD_PORT_MRP_IC_DATA_CHECK = 0x8056
PD_PORT_MRP_IC_DATA_REAL = 0x8057

# =============================================================================
# Sync/PTCP Indices
# =============================================================================

PD_IR_SUBFRAME_DATA = 0x8020
ISOCHRONOUS_MODE_DATA = 0x8030
PD_TIME_DATA = 0x8031

# =============================================================================
# I/O Data Indices
# =============================================================================

SUBSTITUTE_VALUES = 0x801E
RECORD_INPUT_DATA = 0x8028
RECORD_OUTPUT_DATA = 0x8029

# =============================================================================
# Asset Management Indices
# =============================================================================

AM_DEVICE_ID = 0xF8E0
AM_FULL_INFO = 0xF8E1
AM_HW_ONLY = 0xF8E2
AM_FW_ONLY = 0xF8E3
AM_LOCATION_SLOT = 0xFBE0
AM_LOCATION_TREE = 0xFBE1
AM_DATA = 0xFBF0

# =============================================================================
# PROFIsafe Indices
# =============================================================================

F_PARAMETER_BLOCK = 0x0100
F_PRM_FLAG1 = 0x0101
F_PRM_FLAG2 = 0x0102
F_PARAMETER_WRITE = 0xE000
F_PARAMETER_READ = 0xE001

# =============================================================================
# PROFIenergy Index
# =============================================================================

PROFIENERGY = 0x80A0

# =============================================================================
# AR-specific Indices
# =============================================================================

WRITE_MULTIPLE = 0xE040
AR_FSU_DATA_ADJUST = 0xE050

# =============================================================================
# Standard DAP Subslots
# =============================================================================

SUBSLOT_DAP = 0x0001
SUBSLOT_INTERFACE = 0x8000
SUBSLOT_PORT1 = 0x8001
SUBSLOT_PORT2 = 0x8002


# =============================================================================
# Index Categories for Enumeration
# =============================================================================

# Critical indices that should always be tested
CRITICAL_INDICES: List[Tuple[int, str]] = [
    (IM0, "I&M0 (mandatory)"),
    (IM0_FILTER_DATA, "I&M0FilterData"),
    (DIAG_DEVICE, "Device Diagnosis"),
    (MODULE_DIFF_BLOCK, "ModuleDiffBlock"),
    (PD_REAL_DATA, "PDRealData"),
    (AR_DATA, "ARData"),
    (LOG_DATA, "LogData"),
]

# I&M indices
IM_INDICES: List[Tuple[int, str]] = [
    (IM0, "I&M0"),
    (IM1, "I&M1"),
    (IM2, "I&M2"),
    (IM3, "I&M3"),
    (IM4, "I&M4"),
    (IM5, "I&M5"),
    (IM6, "I&M6"),
    (IM7, "I&M7"),
    (IM8, "I&M8"),
    (IM9, "I&M9"),
    (IM10, "I&M10"),
    (IM11, "I&M11"),
    (IM12, "I&M12"),
    (IM13, "I&M13"),
    (IM14, "I&M14"),
    (IM15, "I&M15"),
]

# Diagnosis indices by scope
DIAGNOSIS_INDICES: Dict[str, List[Tuple[int, str]]] = {
    "subslot": [
        (DIAG_CHANNEL_SUBSLOT, "DiagnosisChannel"),
        (DIAG_ALL_SUBSLOT, "DiagnosisAll"),
        (DIAG_MAINTENANCE_SUBSLOT, "DiagnosisMaintenance"),
    ],
    "slot": [
        (DIAG_CHANNEL_SLOT, "DiagnosisChannel"),
        (DIAG_ALL_SLOT, "DiagnosisAll"),
        (DIAG_MAINTENANCE_SLOT, "DiagnosisMaintenance"),
    ],
    "ar": [
        (DIAG_CHANNEL_AR, "DiagnosisChannel"),
        (DIAG_ALL_AR, "DiagnosisAll"),
        (DIAG_MAINTENANCE_AR, "DiagnosisMaintenance"),
    ],
    "api": [
        (DIAG_CHANNEL_API, "DiagnosisChannel"),
        (DIAG_ALL_API, "DiagnosisAll"),
        (DIAG_MAINTENANCE_API, "DiagnosisMaintenance"),
    ],
    "device": [
        (DIAG_DEVICE, "DeviceDiagnosis"),
    ],
}

# Port-related indices
PORT_INDICES: List[Tuple[int, str]] = [
    (PD_PORT_DATA_REAL, "PDPortDataReal"),
    (PD_PORT_DATA_CHECK, "PDPortDataCheck"),
    (PD_PORT_DATA_ADJUST, "PDPortDataAdjust"),
    (PD_PORT_STATISTIC, "PDPortStatistic"),
    (PD_PORT_MRP_DATA_REAL, "PDPortMrpDataReal"),
]

# Interface-related indices
INTERFACE_INDICES: List[Tuple[int, str]] = [
    (PD_INTERFACE_DATA_REAL, "PDInterfaceDataReal"),
    (PD_INTERFACE_MRP_DATA_REAL, "PDInterfaceMrpDataReal"),
    (PD_NC_DATA_CHECK, "PDNCDataCheck"),
]

# Device-level indices
DEVICE_INDICES: List[Tuple[int, str]] = [
    (AR_DATA, "ARData"),
    (API_DATA, "APIData"),
    (PDEV_DATA, "PDevData"),
    (PD_REAL_DATA, "PDRealData"),
    (PD_EXPECTED_DATA, "PDExpectedData"),
    (LOG_DATA, "LogData"),
    (AUTO_CONFIG, "AutoConfiguration"),
]

# All standard indices for comprehensive enumeration
ALL_STANDARD_INDICES: List[Tuple[int, str]] = (
    IM_INDICES
    + DIAGNOSIS_INDICES["subslot"]
    + DIAGNOSIS_INDICES["device"]
    + PORT_INDICES
    + INTERFACE_INDICES
    + DEVICE_INDICES
    + [
        (EXPECTED_ID_SUBSLOT, "ExpectedIdentificationData"),
        (REAL_ID_SUBSLOT, "RealIdentificationData"),
        (MODULE_DIFF_BLOCK, "ModuleDiffBlock"),
        (SUBSTITUTE_VALUES, "SubstituteValues"),
        (RECORD_INPUT_DATA, "RecordInputData"),
        (RECORD_OUTPUT_DATA, "RecordOutputData"),
    ]
)


def get_index_name(index: int) -> str:
    """Get human-readable name for an index."""
    for idx, name in ALL_STANDARD_INDICES:
        if idx == index:
            return name

    # Check range for category
    if 0x0000 <= index <= 0x7FFF:
        return f"User-specific (0x{index:04X})"
    elif 0xAFF0 <= index <= 0xAFFF:
        return f"I&M{index - 0xAFF0}"
    elif 0x8000 <= index <= 0x8FFF:
        return f"Subslot data (0x{index:04X})"
    elif 0xC000 <= index <= 0xCFFF:
        return f"Slot data (0x{index:04X})"
    elif 0xE000 <= index <= 0xEFFF:
        return f"AR data (0x{index:04X})"
    elif 0xF000 <= index <= 0xF7FF:
        return f"API data (0x{index:04X})"
    elif 0xF800 <= index <= 0xFBFF:
        return f"Device data (0x{index:04X})"
    else:
        return f"Unknown (0x{index:04X})"


def get_scope(index: int) -> str:
    """Get the addressing scope for an index."""
    if 0x0000 <= index <= 0x7FFF:
        return "user"
    elif 0x8000 <= index <= 0x8FFF:
        return "subslot"
    elif 0xA000 <= index <= 0xAFFF:
        return "slot"
    elif 0xC000 <= index <= 0xCFFF:
        return "slot"
    elif 0xE000 <= index <= 0xEFFF:
        return "ar"
    elif 0xF000 <= index <= 0xF7FF:
        return "api"
    elif 0xF800 <= index <= 0xFBFF:
        return "device"
    else:
        return "unknown"
