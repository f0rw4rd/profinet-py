"""Fixtures and skip conditions for profinet-py integration tests.

These tests require:
- Root privileges (raw sockets need CAP_NET_RAW)
- The profinet-test-device Docker container running
- A network interface accessible to the container (host networking)

Environment variables:
    PROFINET_TEST_IFACE  - Network interface name (default: eth0)
    PROFINET_TEST_STATION - Expected station name (default: test-pn-device)
"""

import os
import subprocess

import pytest

# ---------------------------------------------------------------------------
# Expected device properties from the p-net mock device GSDML header
# ---------------------------------------------------------------------------

EXPECTED_STATION_NAME = os.environ.get("PROFINET_TEST_STATION", "test-pn-device")
EXPECTED_VENDOR_ID = 0x0493
EXPECTED_DEVICE_ID = 0x0002
EXPECTED_OEM_VENDOR_ID = 0xCAFE
EXPECTED_OEM_DEVICE_ID = 0xEE02
EXPECTED_HW_REVISION = 1
EXPECTED_SW_REVISION_PREFIX = ord("V")
EXPECTED_SW_REVISION_MAJOR = 0
EXPECTED_SW_REVISION_MINOR = 2
EXPECTED_SERIAL_NUMBER = "PNMOCK-001"
EXPECTED_ORDER_ID = "PNMOCK-DEV-001"
EXPECTED_PRODUCT_NAME = "PROFINET Mock IO Device"
EXPECTED_IM1_TAG_FUNCTION = "PN Mock Device"
EXPECTED_IM1_TAG_LOCATION = "Lab Network"
EXPECTED_IM2_DATE = "2024-01-01 00:00"
EXPECTED_IM3_DESCRIPTOR = "PROFINET Mock Emulation"
EXPECTED_PROFILE_ID = 0x1234
EXPECTED_PROFILE_SPEC_TYPE = 0x5678

# ---------------------------------------------------------------------------
# GSDML I/O module definitions for cyclic IO testing
# ---------------------------------------------------------------------------

GSDML_MOD_DIGITAL_IN = 0x00000030
GSDML_SUBMOD_DIGITAL_IN = 0x00000130
GSDML_MOD_DIGITAL_OUT = 0x00000031
GSDML_SUBMOD_DIGITAL_OUT = 0x00000131
GSDML_MOD_DIGITAL_IO = 0x00000032
GSDML_SUBMOD_DIGITAL_IO = 0x00000132
GSDML_MOD_ECHO = 0x00000040
GSDML_SUBMOD_ECHO = 0x00000140


# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------


def _is_root() -> bool:
    """Check if running as root or with CAP_NET_RAW."""
    return os.geteuid() == 0


def _container_running() -> bool:
    """Check if the profinet-test-device container is running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", "profinet-test-device"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() == "true"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _interface_exists(iface: str) -> bool:
    """Check if network interface exists."""
    try:
        result = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _detect_container_bridge() -> str:
    """Detect the Docker bridge interface for the profinet-test-device container.

    When the container uses a custom Docker bridge network, returns the
    host-side bridge interface name (br-<id>). Falls back to 'eth0'.
    """
    try:
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.NetworkID}}{{end}}",
                "profinet-test-device",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        network_id = result.stdout.strip()
        if network_id:
            bridge_name = f"br-{network_id[:12]}"
            if _interface_exists(bridge_name):
                return bridge_name
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return "eth0"


skip_not_root = pytest.mark.skipif(
    not _is_root(),
    reason="Requires root (raw sockets need CAP_NET_RAW)",
)

skip_no_container = pytest.mark.skipif(
    not _container_running(),
    reason="Docker container 'profinet-test-device' is not running",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def interface() -> str:
    """Network interface name for integration tests.

    Auto-detects the Docker bridge interface when PROFINET_TEST_IFACE
    is not set and the container uses bridge networking.
    """
    iface = os.environ.get("PROFINET_TEST_IFACE")
    if iface is None:
        iface = _detect_container_bridge()
    if not _interface_exists(iface):
        pytest.skip(f"Network interface '{iface}' not found")
    return iface


@pytest.fixture(scope="session")
def station_name() -> str:
    """Expected station name of the test device."""
    return EXPECTED_STATION_NAME


@pytest.fixture(scope="session")
def device_properties() -> dict:
    """Expected device properties from the GSDML header."""
    return {
        "station_name": EXPECTED_STATION_NAME,
        "vendor_id": EXPECTED_VENDOR_ID,
        "device_id": EXPECTED_DEVICE_ID,
        "oem_vendor_id": EXPECTED_OEM_VENDOR_ID,
        "oem_device_id": EXPECTED_OEM_DEVICE_ID,
        "hw_revision": EXPECTED_HW_REVISION,
        "sw_revision_prefix": EXPECTED_SW_REVISION_PREFIX,
        "sw_revision_major": EXPECTED_SW_REVISION_MAJOR,
        "sw_revision_minor": EXPECTED_SW_REVISION_MINOR,
        "serial_number": EXPECTED_SERIAL_NUMBER,
        "order_id": EXPECTED_ORDER_ID,
        "product_name": EXPECTED_PRODUCT_NAME,
        "im1_tag_function": EXPECTED_IM1_TAG_FUNCTION,
        "im1_tag_location": EXPECTED_IM1_TAG_LOCATION,
        "im2_date": EXPECTED_IM2_DATE,
        "im3_descriptor": EXPECTED_IM3_DESCRIPTOR,
        "profile_id": EXPECTED_PROFILE_ID,
        "profile_spec_type": EXPECTED_PROFILE_SPEC_TYPE,
    }
