"""
PROFINET exception hierarchy.

Provides specific exception types for different error conditions.
"""

from __future__ import annotations


class ProfinetError(Exception):
    """Base exception for all PROFINET errors."""

    pass


class DCPError(ProfinetError):
    """DCP protocol errors."""

    pass


class DCPTimeoutError(DCPError):
    """DCP operation timed out."""

    pass


class DCPDeviceNotFoundError(DCPError):
    """Device not found via DCP."""

    pass


class RPCError(ProfinetError):
    """DCE/RPC protocol errors."""

    pass


class RPCTimeoutError(RPCError):
    """RPC operation timed out."""

    pass


class RPCFaultError(RPCError):
    """RPC returned fault response."""

    def __init__(self, message: str, fault_code: int = 0):
        super().__init__(message)
        self.fault_code = fault_code


class RPCConnectionError(RPCError):
    """Failed to establish RPC connection."""

    pass


class PNIOError(RPCError):
    """PNIO application error with error codes.

    Error code structure (4 bytes):
        Byte 0: ErrorCode (0x01=App, 0xCF=RTA, 0xDA=AlarmAck, 0xDB=IODConn, etc.)
        Byte 1: ErrorDecode (0x40=PNIO-CM, 0x80=PNIORW, 0x81=PNIO)
        Byte 2: ErrorCode1 (category/block type)
        Byte 3: ErrorCode2 (specific error)

    For PNIO read/write (ErrorDecode=0x80):
        ErrorCode1 = 0xB0-0xB9 (index, write, resource, access, application errors)

    For PNIO-CM (ErrorDecode=0x40):
        ErrorCode1 = block type reference (e.g., 0x01=AR, 0x02=IOCR, 0x03=AlarmCR)
        ErrorCode2 = specific error within that block type
    """

    # ErrorDecode values
    DECODE_PNIO_CM = 0x40  # Connection Management errors
    DECODE_PNIORW = 0x80  # Read/Write errors
    DECODE_PNIO = 0x81  # General PNIO errors

    # ErrorCode values
    PNIO_ERROR = 0xDE
    ERROR_APP = 0x01  # Application error
    ERROR_RTA = 0xCF  # RTA error
    ERROR_ALARM_ACK = 0xDA  # Alarm Ack error
    ERROR_IOD_CONN = 0xDB  # IOD Connect error
    ERROR_IOD_REL = 0xDC  # IOD Release error
    ERROR_IOD_CTRL = 0xDD  # IOD Control error
    ERROR_IOD_RW = 0xDE  # IOD Read/Write error
    ERROR_MPM = 0xDF  # MPM error

    # ErrorCode1 categories for PNIORW (ErrorDecode=0x80) per IEC 61158-6
    EC1_INVALID_INDEX = 0xB0  # Invalid index
    EC1_WRITE_LENGTH = 0xB1  # Write length error
    EC1_RESOURCE = 0xB2  # Slot/Subslot errors
    EC1_ACCESS = 0xB3  # Access errors
    EC1_APPLICATION = 0xB4  # API errors
    EC1_USER_SPECIFIC_1 = 0xB5
    EC1_USER_SPECIFIC_2 = 0xB6
    EC1_USER_SPECIFIC_3 = 0xB7
    EC1_USER_SPECIFIC_4 = 0xB8
    EC1_USER_SPECIFIC_5 = 0xB9

    # ErrorCode2 for EC1_INVALID_INDEX (0xB0)
    EC2_INDEX_UNSUPPORTED = 0x00
    EC2_INDEX_NOT_WRITTEN = 0x05  # Index exists but not written yet

    # ErrorCode2 for EC1_WRITE_LENGTH (0xB1)
    EC2_WRITE_LENGTH_ERROR = 0x00
    EC2_WRITE_TOO_SHORT = 0x01
    EC2_WRITE_TOO_LONG = 0x02
    EC2_WRITE_ACCESS_DENIED = 0x03  # Write protected

    # ErrorCode2 for EC1_RESOURCE (0xB2)
    EC2_INVALID_SLOT = 0x07
    EC2_INVALID_SUBSLOT = 0x08
    EC2_MODULE_NO_DATA = 0x09  # No data for this module

    # ErrorCode2 for EC1_ACCESS (0xB3)
    EC2_ACCESS_INVALID_AREA = 0x00
    EC2_ACCESS_DENIED = 0x03
    EC2_ACCESS_INVALID_RANGE = 0x04
    EC2_ACCESS_INVALID_STATE = 0x05
    EC2_ACCESS_DENIED_LOCAL = 0x06

    # ErrorCode2 for EC1_APPLICATION (0xB4)
    EC2_READ_ERROR = 0x00
    EC2_WRITE_ERROR = 0x01
    EC2_MODULE_FAILURE = 0x02
    EC2_BUSY = 0x04
    EC2_VERSION_CONFLICT = 0x05
    EC2_INVALID_API = 0x06
    EC2_NOT_BACKUP_ALLOWED = 0x07
    EC2_ALARM_PENDING = 0x08

    # PNIO-CM ErrorCode1 values (block type references)
    # Request blocks (0x01-0x0F)
    CM_EC1_AR = 0x01  # ARBlockReq error
    CM_EC1_IOCR = 0x02  # IOCRBlockReq error
    CM_EC1_ALARM_CR = 0x03  # AlarmCRBlockReq error
    CM_EC1_EXPECTED_SUBMOD = 0x04  # ExpectedSubmoduleBlockReq error
    CM_EC1_MODULE_DIFF = 0x05  # ModuleDiffBlock error
    CM_EC1_AR_RPC = 0x06  # AR-RPC error
    # Response blocks (0x81-0x8F = 0x80 | request type)
    CM_EC1_AR_RES = 0x81  # ARBlockRes error
    CM_EC1_IOCR_RES = 0x82  # IOCRBlockRes error
    CM_EC1_ALARM_CR_RES = 0x83  # AlarmCRBlockRes error
    CM_EC1_MODULE_DIFF_RES = 0x84  # ModuleDiffBlockRes error
    # CM internal
    CM_EC1_PRM_SERVER = 0x3D  # Parameter server errors
    CM_EC1_CMCTL = 0x3E  # CM Controller errors
    CM_EC1_CMDEV = 0x3F  # CM Device errors
    CM_EC1_RMPM = 0x40  # Remote Protocol Machine errors
    CM_EC1_FAULTY_RECORD = 0xFD  # Faulty record
    CM_EC1_FAULTY_AR = 0xFE  # Faulty AR block
    CM_EC1_FAULTY_BLOCK = 0xFF  # Faulty block (general)

    # PNIO ErrorCode2 values for RMPM (CM_EC1_RMPM = 0x40)
    RMPM_ARGS_LEN_INVALID = 0x00  # Invalid argument length
    RMPM_UNKNOWN_BLOCKS = 0x01  # Unknown blocks in request
    RMPM_IOCR_MISSING = 0x02  # Required IOCR missing
    RMPM_WRONG_ALCR_COUNT = 0x03  # Wrong AlarmCR block count
    RMPM_OUT_OF_AR_RESOURCES = 0x04  # Out of AR resources

    # PNIO-CM ErrorCode2 values for AR (CM_EC1_AR = 0x01)
    CM_AR_INVALID_TYPE = 0x00  # Invalid AR type
    CM_AR_ALREADY_ACTIVE = 0x01  # AR already active
    CM_AR_OUT_OF_AR = 0x02  # Out of AR resources
    CM_AR_OUT_OF_PROVIDER = 0x03  # Out of provider resources
    CM_AR_OUT_OF_CONSUMER = 0x04  # Out of consumer resources
    CM_AR_OUT_OF_ALARM = 0x05  # Out of alarm resources
    CM_AR_OUT_OF_MEMORY = 0x06  # Out of memory
    CM_AR_INVALID_SESSION = 0x07  # Invalid session key
    CM_AR_UUID_CONFLICT = 0x08  # AR UUID conflict

    # PNIO-CM ErrorCode2 values for IOCR (CM_EC1_IOCR = 0x02)
    CM_IOCR_INVALID_TYPE = 0x00  # Invalid IOCR type
    CM_IOCR_OUT_OF_RESOURCES = 0x01  # Out of IOCR resources
    CM_IOCR_INVALID_FRAME_ID = 0x02  # Invalid frame ID
    CM_IOCR_INVALID_RT_CLASS = 0x03  # Invalid RT class
    CM_IOCR_INVALID_DATA_LEN = 0x04  # Invalid data length
    CM_IOCR_CYCLE_CONFLICT = 0x05  # Cycle time conflict
    CM_IOCR_WATCHDOG_ERR = 0x06  # Watchdog error

    # PNIO-CM ErrorCode2 values for ExpectedSubmodule (CM_EC1_EXPECTED_SUBMOD = 0x04)
    CM_SUBMOD_INVALID_SLOT = 0x00  # Invalid slot
    CM_SUBMOD_INVALID_SUBSLOT = 0x01  # Invalid subslot
    CM_SUBMOD_WRONG_MODULE = 0x02  # Wrong module ident
    CM_SUBMOD_WRONG_SUBMOD = 0x03  # Wrong submodule ident
    CM_SUBMOD_IO_LEN_MISMATCH = 0x04  # IO length mismatch

    # PNIO-CM ErrorCode2 values for CMDEV (CM_EC1_CMDEV = 0x3F)
    CM_DEV_STATE_CONFLICT = 0x00  # Device state conflict
    CM_DEV_CONNECT_RESOURCE = 0x01  # Connect resource error
    CM_DEV_ALREADY_OWNED = 0x02  # Already owned by another AR
    CM_DEV_AR_SET_ABORT = 0x03  # AR set abort

    # Human-readable error messages for PNIORW (ErrorDecode=0x80)
    PNIORW_ERROR_MESSAGES = {
        # EC1=0xB0 Invalid Index
        (EC1_INVALID_INDEX, 0x00): "Index not supported",
        (EC1_INVALID_INDEX, 0x05): "Index exists but not written",
        # EC1=0xB1 Write Length
        (EC1_WRITE_LENGTH, 0x00): "Write length error",
        (EC1_WRITE_LENGTH, 0x01): "Write data too short",
        (EC1_WRITE_LENGTH, 0x02): "Write data too long",
        (EC1_WRITE_LENGTH, 0x03): "Write access denied (write protected)",
        # EC1=0xB2 Resource
        (EC1_RESOURCE, 0x00): "Resource not available",
        (EC1_RESOURCE, EC2_INVALID_SLOT): "Invalid slot number",
        (EC1_RESOURCE, EC2_INVALID_SUBSLOT): "Invalid subslot number",
        (EC1_RESOURCE, EC2_MODULE_NO_DATA): "Module has no data",
        # EC1=0xB3 Access
        (EC1_ACCESS, 0x00): "Access denied (invalid area)",
        (EC1_ACCESS, 0x03): "Access denied",
        (EC1_ACCESS, 0x04): "Access denied (invalid range)",
        (EC1_ACCESS, 0x05): "Access denied (invalid state for access)",
        (EC1_ACCESS, 0x06): "Access denied (local control)",
        # EC1=0xB4 Application
        (EC1_APPLICATION, 0x00): "Read error",
        (EC1_APPLICATION, 0x01): "Write error",
        (EC1_APPLICATION, 0x02): "Module failure",
        (EC1_APPLICATION, 0x04): "Resource busy",
        (EC1_APPLICATION, 0x05): "Version conflict",
        (EC1_APPLICATION, EC2_INVALID_API): "Invalid API number",
        (EC1_APPLICATION, 0x07): "Backup not allowed",
        (EC1_APPLICATION, 0x08): "Alarm pending",
    }

    # Human-readable error messages for PNIO (ErrorDecode=0x81)
    # Includes RMPM (Remote Protocol Machine) errors
    PNIO_ERROR_MESSAGES = {
        # RMPM errors (EC1=0x40)
        (CM_EC1_RMPM, RMPM_ARGS_LEN_INVALID): "Invalid arguments length",
        (CM_EC1_RMPM, RMPM_UNKNOWN_BLOCKS): "Unknown blocks in request",
        (CM_EC1_RMPM, RMPM_IOCR_MISSING): "Required IOCR block missing",
        (CM_EC1_RMPM, RMPM_WRONG_ALCR_COUNT): "Wrong AlarmCR block count",
        (CM_EC1_RMPM, RMPM_OUT_OF_AR_RESOURCES): "Out of AR resources",
        # CMDEV errors (EC1=0x3D) when ErrorDecode=0x81
        (CM_EC1_PRM_SERVER, 0x00): "Parameter server state conflict",
    }

    # Human-readable error messages for PNIO-CM (ErrorDecode=0x40)
    PNIOCM_ERROR_MESSAGES = {
        # AR Request errors (EC1=0x01)
        (CM_EC1_AR, CM_AR_INVALID_TYPE): "Invalid AR type",
        (CM_EC1_AR, CM_AR_ALREADY_ACTIVE): "AR already active",
        (CM_EC1_AR, CM_AR_OUT_OF_AR): "Out of AR resources",
        (CM_EC1_AR, CM_AR_OUT_OF_PROVIDER): "Out of provider resources",
        (CM_EC1_AR, CM_AR_OUT_OF_CONSUMER): "Out of consumer resources",
        (CM_EC1_AR, CM_AR_OUT_OF_ALARM): "Out of alarm resources",
        (CM_EC1_AR, CM_AR_OUT_OF_MEMORY): "Out of memory",
        (CM_EC1_AR, CM_AR_INVALID_SESSION): "Invalid session key",
        (CM_EC1_AR, CM_AR_UUID_CONFLICT): "AR UUID conflict",
        # AR Response errors (EC1=0x81) - same error codes, response context
        (CM_EC1_AR_RES, CM_AR_INVALID_TYPE): "Invalid AR type (in response)",
        (CM_EC1_AR_RES, CM_AR_ALREADY_ACTIVE): "AR already active",
        (CM_EC1_AR_RES, CM_AR_OUT_OF_AR): "Out of AR resources",
        (CM_EC1_AR_RES, CM_AR_OUT_OF_PROVIDER): "Out of provider resources",
        (CM_EC1_AR_RES, CM_AR_OUT_OF_CONSUMER): "Out of consumer resources",
        (CM_EC1_AR_RES, CM_AR_OUT_OF_ALARM): "Out of alarm resources",
        (CM_EC1_AR_RES, CM_AR_OUT_OF_MEMORY): "Out of memory",
        (CM_EC1_AR_RES, CM_AR_INVALID_SESSION): "Invalid session key",
        (CM_EC1_AR_RES, CM_AR_UUID_CONFLICT): "AR UUID conflict",
        # IOCR Request errors (EC1=0x02)
        (CM_EC1_IOCR, CM_IOCR_INVALID_TYPE): "Invalid IOCR type",
        (CM_EC1_IOCR, CM_IOCR_OUT_OF_RESOURCES): "Out of IOCR resources",
        (CM_EC1_IOCR, CM_IOCR_INVALID_FRAME_ID): "Invalid frame ID",
        (CM_EC1_IOCR, CM_IOCR_INVALID_RT_CLASS): "Invalid RT class",
        (CM_EC1_IOCR, CM_IOCR_INVALID_DATA_LEN): "Invalid IO data length",
        (CM_EC1_IOCR, CM_IOCR_CYCLE_CONFLICT): "Cycle time conflict",
        (CM_EC1_IOCR, CM_IOCR_WATCHDOG_ERR): "Watchdog configuration error",
        # IOCR Response errors (EC1=0x82)
        (CM_EC1_IOCR_RES, CM_IOCR_INVALID_TYPE): "Invalid IOCR type (in response)",
        (CM_EC1_IOCR_RES, CM_IOCR_OUT_OF_RESOURCES): "Out of IOCR resources",
        (CM_EC1_IOCR_RES, CM_IOCR_INVALID_FRAME_ID): "Invalid frame ID",
        (CM_EC1_IOCR_RES, CM_IOCR_INVALID_RT_CLASS): "Invalid RT class",
        (CM_EC1_IOCR_RES, CM_IOCR_INVALID_DATA_LEN): "Invalid IO data length",
        (CM_EC1_IOCR_RES, CM_IOCR_CYCLE_CONFLICT): "Cycle time conflict",
        (CM_EC1_IOCR_RES, CM_IOCR_WATCHDOG_ERR): "Watchdog configuration error",
        # AlarmCR errors (EC1=0x03)
        (CM_EC1_ALARM_CR, 0x00): "Invalid AlarmCR type",
        (CM_EC1_ALARM_CR, 0x01): "Out of AlarmCR resources",
        (CM_EC1_ALARM_CR_RES, 0x00): "Invalid AlarmCR type (in response)",
        (CM_EC1_ALARM_CR_RES, 0x01): "Out of AlarmCR resources",
        # ExpectedSubmodule errors (EC1=0x04)
        (CM_EC1_EXPECTED_SUBMOD, CM_SUBMOD_INVALID_SLOT): "Invalid slot in ExpectedSubmodule",
        (CM_EC1_EXPECTED_SUBMOD, CM_SUBMOD_INVALID_SUBSLOT): "Invalid subslot in ExpectedSubmodule",
        (CM_EC1_EXPECTED_SUBMOD, CM_SUBMOD_WRONG_MODULE): "Wrong module ident number",
        (CM_EC1_EXPECTED_SUBMOD, CM_SUBMOD_WRONG_SUBMOD): "Wrong submodule ident number",
        (CM_EC1_EXPECTED_SUBMOD, CM_SUBMOD_IO_LEN_MISMATCH): "IO data length mismatch",
        # CMDEV errors (EC1=0x3F)
        (CM_EC1_CMDEV, CM_DEV_STATE_CONFLICT): "Device state conflict (AR may be active)",
        (CM_EC1_CMDEV, CM_DEV_CONNECT_RESOURCE): "Connect resource unavailable",
        (CM_EC1_CMDEV, CM_DEV_ALREADY_OWNED): "Device already owned by another controller",
        (CM_EC1_CMDEV, CM_DEV_AR_SET_ABORT): "AR set aborted",
        # Faulty block errors (EC1=0xFF)
        (CM_EC1_FAULTY_BLOCK, 0x00): "Faulty block structure",
    }

    # Block type names for PNIO-CM (request and response blocks)
    CM_BLOCK_NAMES = {
        # Request blocks (0x01-0x0F)
        0x01: "ARBlockReq",
        0x02: "IOCRBlockReq",
        0x03: "AlarmCRBlockReq",
        0x04: "ExpectedSubmoduleBlockReq",
        0x05: "ModuleDiffBlock",
        0x06: "ARRPCBlock",
        0x07: "IRInfoBlock",
        0x08: "SRInfoBlock",
        0x09: "ARFSUBlock",
        0x10: "IODControlReq",
        0x11: "IODControlRes",
        # Response blocks (0x81-0x8F = 0x80 | request type)
        0x81: "ARBlockRes",
        0x82: "IOCRBlockRes",
        0x83: "AlarmCRBlockRes",
        0x84: "ModuleDiffBlockRes",
        0x85: "ARServerBlockRes",
        # CM internal blocks
        0x3D: "PrmServer",
        0x3E: "CMCTL",
        0x3F: "CMDEV",
        0x40: "CMRPC",
        # Faulty blocks
        0xFD: "FaultyRecord",
        0xFE: "FaultyAR",
        0xFF: "FaultyBlock",
    }

    # Legacy alias for backward compatibility
    ERROR_MESSAGES = PNIORW_ERROR_MESSAGES

    def __init__(
        self,
        message: str,
        error_code: int = 0,
        error_decode: int = 0,
        error_code1: int = 0,
        error_code2: int = 0,
    ):
        super().__init__(message)
        self.error_code = error_code
        self.error_decode = error_decode
        self.error_code1 = error_code1
        self.error_code2 = error_code2

    @classmethod
    def from_bytes(cls, data: bytes) -> PNIOError:
        """Create PNIOError from 4-byte error status.

        Args:
            data: 4 bytes in format [ErrorCode, ErrorDecode, ErrorCode1, ErrorCode2]

        Returns:
            PNIOError with parsed error codes and human-readable message
        """
        if len(data) < 4:
            return cls("Incomplete error data", 0, 0, 0, 0)

        error_code = data[0]
        error_decode = data[1]
        error_code1 = data[2]
        error_code2 = data[3]

        return cls._create_from_codes(error_code, error_decode, error_code1, error_code2)

    @classmethod
    def from_args_status(cls, args_status: int) -> PNIOError:
        """Create PNIOError from ArgsStatus field.

        Note: make_packet parses ArgsMaximumStatus as big-endian (">I"),
        but DCE/RPC uses little-endian. We byte-swap to get correct values
        matching Hilscher format:
            Bits 31-24: ErrorCode  (service type: 0xDB=Connect, 0xDE=Read/Write)
            Bits 23-16: ErrorDecode (0x81=PNIO, 0x80=PNIORW)
            Bits 15-8:  ErrorCode1 (category)
            Bits 7-0:   ErrorCode2 (specific error)

        Example: Wire bytes [0x01,0x40,0x81,0xDB] → big-endian parse 0x014081DB
                 → byte-swap → 0xDB814001 = RMPM Connect Unknown Blocks
        """
        # Byte-swap to convert from big-endian parsed value to Hilscher format
        swapped = (
            ((args_status & 0xFF) << 24)
            | (((args_status >> 8) & 0xFF) << 16)
            | (((args_status >> 16) & 0xFF) << 8)
            | ((args_status >> 24) & 0xFF)
        )

        # Now extract in Hilscher order
        error_code = (swapped >> 24) & 0xFF
        error_decode = (swapped >> 16) & 0xFF
        error_code1 = (swapped >> 8) & 0xFF
        error_code2 = swapped & 0xFF

        return cls._create_from_codes(error_code, error_decode, error_code1, error_code2)

    @classmethod
    def _create_from_codes(
        cls,
        error_code: int,
        error_decode: int,
        error_code1: int,
        error_code2: int,
    ) -> PNIOError:
        """Create PNIOError with human-readable message from error codes."""
        key = (error_code1, error_code2)

        # Select message table based on ErrorDecode
        if error_decode == cls.DECODE_PNIO_CM:
            # PNIO-CM (Connection Management) error
            if key in cls.PNIOCM_ERROR_MESSAGES:
                msg = cls.PNIOCM_ERROR_MESSAGES[key]
            else:
                # Unknown CM error - block name will be shown in __str__
                block_name = cls.CM_BLOCK_NAMES.get(error_code1, f"block 0x{error_code1:02X}")
                msg = f"Unknown CM error in {block_name}"
        elif error_decode == cls.DECODE_PNIO:
            # PNIO error (includes RMPM errors)
            if key in cls.PNIO_ERROR_MESSAGES:
                msg = cls.PNIO_ERROR_MESSAGES[key]
            elif key in cls.PNIORW_ERROR_MESSAGES:
                msg = cls.PNIORW_ERROR_MESSAGES[key]
            else:
                msg = "Unknown PNIO error"
        elif error_decode == cls.DECODE_PNIORW:
            # PNIO Read/Write error
            if key in cls.PNIORW_ERROR_MESSAGES:
                msg = cls.PNIORW_ERROR_MESSAGES[key]
            else:
                msg = "Unknown PNIORW error"
        else:
            msg = f"Unknown error (Decode=0x{error_decode:02X})"

        return cls(
            message=msg,
            error_code=error_code,
            error_decode=error_decode,
            error_code1=error_code1,
            error_code2=error_code2,
        )

    @property
    def is_cm_error(self) -> bool:
        """True if this is a Connection Management error."""
        return self.error_decode == self.DECODE_PNIO_CM

    @property
    def block_name(self) -> str:
        """Get the block name for CM errors."""
        if self.is_cm_error:
            return self.CM_BLOCK_NAMES.get(self.error_code1, f"Unknown(0x{self.error_code1:02X})")
        return ""

    def __str__(self) -> str:
        if self.is_cm_error:
            block = self.block_name
            return f"{self.args[0]} [CM:{block}, EC2=0x{self.error_code2:02X}]"
        else:
            return (
                f"{self.args[0]} "
                f"[ErrorCode1=0x{self.error_code1:02X}, ErrorCode2=0x{self.error_code2:02X}]"
            )

    def __repr__(self) -> str:
        return (
            f"PNIOError(code=0x{self.error_code:02X}, decode=0x{self.error_decode:02X}, "
            f"ec1=0x{self.error_code1:02X}, ec2=0x{self.error_code2:02X})"
        )


class ValidationError(ProfinetError):
    """Input validation error."""

    pass


class InvalidMACError(ValidationError):
    """Invalid MAC address format."""

    pass


class InvalidIPError(ValidationError):
    """Invalid IP address format."""

    pass


class SocketError(ProfinetError):
    """Socket operation error."""

    pass


class PermissionDeniedError(SocketError):
    """Insufficient permissions for raw socket."""

    pass
