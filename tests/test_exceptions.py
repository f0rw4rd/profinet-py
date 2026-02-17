"""Tests for profinet.exceptions module."""

import pytest

from profinet.exceptions import (
    DCPDeviceNotFoundError,
    DCPError,
    DCPTimeoutError,
    InvalidIPError,
    InvalidMACError,
    PermissionDeniedError,
    PNIOError,
    ProfinetError,
    RPCConnectionError,
    RPCError,
    RPCFaultError,
    RPCTimeoutError,
    SocketError,
    ValidationError,
)


class TestExceptionHierarchy:
    """Test exception inheritance hierarchy."""

    def test_dcp_error_inherits_profinet_error(self):
        """Test DCPError inherits from ProfinetError."""
        assert issubclass(DCPError, ProfinetError)

    def test_dcp_timeout_inherits_dcp_error(self):
        """Test DCPTimeoutError inherits from DCPError."""
        assert issubclass(DCPTimeoutError, DCPError)

    def test_dcp_device_not_found_inherits_dcp_error(self):
        """Test DCPDeviceNotFoundError inherits from DCPError."""
        assert issubclass(DCPDeviceNotFoundError, DCPError)

    def test_rpc_error_inherits_profinet_error(self):
        """Test RPCError inherits from ProfinetError."""
        assert issubclass(RPCError, ProfinetError)

    def test_rpc_timeout_inherits_rpc_error(self):
        """Test RPCTimeoutError inherits from RPCError."""
        assert issubclass(RPCTimeoutError, RPCError)

    def test_rpc_fault_inherits_rpc_error(self):
        """Test RPCFaultError inherits from RPCError."""
        assert issubclass(RPCFaultError, RPCError)

    def test_rpc_connection_inherits_rpc_error(self):
        """Test RPCConnectionError inherits from RPCError."""
        assert issubclass(RPCConnectionError, RPCError)

    def test_validation_error_inherits_profinet_error(self):
        """Test ValidationError inherits from ProfinetError."""
        assert issubclass(ValidationError, ProfinetError)

    def test_invalid_mac_inherits_validation_error(self):
        """Test InvalidMACError inherits from ValidationError."""
        assert issubclass(InvalidMACError, ValidationError)

    def test_invalid_ip_inherits_validation_error(self):
        """Test InvalidIPError inherits from ValidationError."""
        assert issubclass(InvalidIPError, ValidationError)

    def test_socket_error_inherits_profinet_error(self):
        """Test SocketError inherits from ProfinetError."""
        assert issubclass(SocketError, ProfinetError)

    def test_permission_denied_inherits_socket_error(self):
        """Test PermissionDeniedError inherits from SocketError."""
        assert issubclass(PermissionDeniedError, SocketError)


class TestRPCFaultError:
    """Test RPCFaultError specific functionality."""

    def test_fault_code_default(self):
        """Test default fault code is 0."""
        error = RPCFaultError("test error")
        assert error.fault_code == 0

    def test_fault_code_custom(self):
        """Test custom fault code."""
        error = RPCFaultError("test error", fault_code=42)
        assert error.fault_code == 42

    def test_message(self):
        """Test error message."""
        error = RPCFaultError("RPC fault occurred")
        assert str(error) == "RPC fault occurred"


class TestExceptionCatching:
    """Test exception catching patterns."""

    def test_catch_all_profinet_errors(self):
        """Test catching all PROFINET errors with base class."""
        errors = [
            DCPError("dcp"),
            RPCError("rpc"),
            ValidationError("validation"),
            SocketError("socket"),
        ]
        for error in errors:
            with pytest.raises(ProfinetError):
                raise error

    def test_catch_dcp_variants(self):
        """Test catching DCP variants with DCPError."""
        errors = [
            DCPTimeoutError("timeout"),
            DCPDeviceNotFoundError("not found"),
        ]
        for error in errors:
            with pytest.raises(DCPError):
                raise error

    def test_catch_rpc_variants(self):
        """Test catching RPC variants with RPCError."""
        errors = [
            RPCTimeoutError("timeout"),
            RPCFaultError("fault"),
            RPCConnectionError("connection"),
            PNIOError("pnio"),
        ]
        for error in errors:
            with pytest.raises(RPCError):
                raise error


class TestPNIOError:
    """Test PNIOError specific functionality."""

    def test_pnio_error_inherits_rpc_error(self):
        """Test PNIOError inherits from RPCError."""
        assert issubclass(PNIOError, RPCError)

    def test_default_values(self):
        """Test default error code values."""
        error = PNIOError("test error")
        assert error.error_code == 0
        assert error.error_decode == 0
        assert error.error_code1 == 0
        assert error.error_code2 == 0

    def test_custom_values(self):
        """Test custom error code values."""
        error = PNIOError(
            "test",
            error_code=0xDE,
            error_decode=0x80,
            error_code1=0xB2,
            error_code2=0x07,
        )
        assert error.error_code == 0xDE
        assert error.error_decode == 0x80
        assert error.error_code1 == 0xB2
        assert error.error_code2 == 0x07

    def test_from_args_status_invalid_slot(self):
        """Test creating PNIOError from ArgsStatus for invalid slot.

        ArgsStatus is byte-swapped from big-endian parse to Hilscher format.
        Wire bytes [0x07, 0xB2, 0x80, 0xDE] → big-endian 0x07B280DE → swap → 0xDE80B207
        """
        # After byte-swap: ErrorCode=0xDE, ErrorDecode=0x80, ErrorCode1=0xB2, ErrorCode2=0x07
        args_status = 0x07B280DE
        error = PNIOError.from_args_status(args_status)

        assert error.error_code == 0xDE
        assert error.error_decode == 0x80
        assert error.error_code1 == 0xB2
        assert error.error_code2 == 0x07
        assert "Invalid slot" in str(error)

    def test_from_args_status_invalid_subslot(self):
        """Test creating PNIOError from ArgsStatus for invalid subslot."""
        # After byte-swap: ErrorCode=0xDE, ErrorDecode=0x80, ErrorCode1=0xB2, ErrorCode2=0x08
        args_status = 0x08B280DE
        error = PNIOError.from_args_status(args_status)

        assert error.error_code == 0xDE
        assert error.error_decode == 0x80
        assert error.error_code1 == 0xB2
        assert error.error_code2 == 0x08
        assert "Invalid subslot" in str(error)

    def test_from_args_status_invalid_index(self):
        """Test creating PNIOError from ArgsStatus for invalid index."""
        # After byte-swap: ErrorCode=0xDE, ErrorDecode=0x80, ErrorCode1=0xB0, ErrorCode2=0x00
        args_status = 0x00B080DE
        error = PNIOError.from_args_status(args_status)

        assert error.error_code == 0xDE
        assert error.error_decode == 0x80
        assert error.error_code1 == 0xB0
        assert error.error_code2 == 0x00
        assert "Index not supported" in str(error)

    def test_from_args_status_invalid_api(self):
        """Test creating PNIOError from ArgsStatus for invalid API."""
        # After byte-swap: ErrorCode=0xDE, ErrorDecode=0x80, ErrorCode1=0xB4, ErrorCode2=0x06
        args_status = 0x06B480DE
        error = PNIOError.from_args_status(args_status)

        assert error.error_code == 0xDE
        assert error.error_decode == 0x80
        assert error.error_code1 == 0xB4
        assert error.error_code2 == 0x06
        assert "Invalid API" in str(error)

    def test_from_args_status_rmpm_error(self):
        """Test creating PNIOError for RMPM connect error (unknown blocks).

        This matches Hilscher constant PNIO_E_RMPM_CONNECT_UNKNOWN_BLOCKS = 0xDB814001
        Wire bytes [0x01, 0x40, 0x81, 0xDB] → big-endian 0x014081DB → swap → 0xDB814001
        """
        args_status = 0x014081DB
        error = PNIOError.from_args_status(args_status)

        assert error.error_code == 0xDB  # IODConnectRes
        assert error.error_decode == 0x81  # PNIO
        assert error.error_code1 == 0x40  # RMPM
        assert error.error_code2 == 0x01  # Unknown blocks
        assert "Unknown blocks" in str(error)

    def test_from_args_status_unknown_error(self):
        """Test creating PNIOError from unknown ArgsStatus."""
        # After byte-swap: ErrorCode=0xDE, ErrorDecode=0x80, ErrorCode1=0xB2, ErrorCode2=0xFF
        args_status = 0xFFB280DE
        error = PNIOError.from_args_status(args_status)

        assert error.error_code == 0xDE
        assert error.error_code2 == 0xFF
        assert "Unknown" in str(error)

    def test_str_format(self):
        """Test string representation format."""
        error = PNIOError(
            "Test message",
            error_code1=0xB2,
            error_code2=0x07,
        )
        result = str(error)
        assert "Test message" in result
        assert "0xB2" in result
        assert "0x07" in result

    def test_error_constants(self):
        """Test error code constants are defined."""
        assert PNIOError.PNIO_ERROR == 0xDE
        assert PNIOError.EC1_INVALID_INDEX == 0xB0
        assert PNIOError.EC1_RESOURCE == 0xB2
        assert PNIOError.EC1_APPLICATION == 0xB4
        assert PNIOError.EC2_INVALID_SLOT == 0x07
        assert PNIOError.EC2_INVALID_SUBSLOT == 0x08
        assert PNIOError.EC2_INVALID_API == 0x06
