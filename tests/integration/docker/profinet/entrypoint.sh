#!/bin/bash
# PROFINET IO Device Emulation - Entrypoint
#
# Configures and launches the p-net sample application as a
# PROFINET IO Device for security testing.
#
# Environment variables:
#   PNET_STATION_NAME  - Device station name (default: pnmock-device)
#   PNET_INTERFACE     - Network interface (default: eth0)
#   PNET_VERBOSITY     - Log verbosity 0-4 (default: 2)

set -e

STATION_NAME="${PNET_STATION_NAME:-pnmock-device}"
INTERFACE="${PNET_INTERFACE:-eth0}"
VERBOSITY="${PNET_VERBOSITY:-2}"
STORAGE_DIR="/var/lib/pnet"

echo "========================================"
echo " PROFINET IO Device Emulation"
echo "========================================"
echo " Station name: ${STATION_NAME}"
echo " Interface:    ${INTERFACE}"
echo " Verbosity:    ${VERBOSITY}"
echo " Storage:      ${STORAGE_DIR}"
echo "========================================"

# Wait for network interface to be available
MAX_WAIT=30
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if ip link show "${INTERFACE}" >/dev/null 2>&1; then
        break
    fi
    echo "Waiting for interface ${INTERFACE}..."
    sleep 1
    WAITED=$((WAITED + 1))
done

if ! ip link show "${INTERFACE}" >/dev/null 2>&1; then
    echo "ERROR: Interface ${INTERFACE} not found after ${MAX_WAIT}s"
    echo "Available interfaces:"
    ip link show
    exit 1
fi

# Show interface info
echo ""
echo "Interface ${INTERFACE} details:"
ip addr show "${INTERFACE}" 2>/dev/null || true
echo ""

# Build verbosity flags
VERBOSE_FLAGS=""
for i in $(seq 1 "${VERBOSITY}"); do
    VERBOSE_FLAGS="${VERBOSE_FLAGS} -v"
done

# Ensure storage directory exists
mkdir -p "${STORAGE_DIR}"

# Remove stale state files on startup for clean state
rm -f "${STORAGE_DIR}"/pnet_data_* 2>/dev/null || true

echo "Starting p-net device (pn_dev)..."
echo "Command: pn_dev -i ${INTERFACE} -s ${STATION_NAME} -p ${STORAGE_DIR} ${VERBOSE_FLAGS}"
echo ""

# Run p-net sample application
# -i: network interface
# -s: station name (used in DCP responses)
# -p: storage directory for persistent state
# -v: verbosity (repeated for more detail)
exec /usr/local/bin/pn_dev \
    -i "${INTERFACE}" \
    -s "${STATION_NAME}" \
    -p "${STORAGE_DIR}" \
    ${VERBOSE_FLAGS}
