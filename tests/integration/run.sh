#!/usr/bin/env bash
# Integration test runner for profinet-py.
#
# Builds and starts the PROFINET device emulator in Docker, waits for it
# to be ready, runs the integration tests, then stops the container.
#
# Usage:
#   sudo ./tests/integration/run.sh [INTERFACE]
#
# Arguments:
#   INTERFACE  Network interface for PROFINET (default: eth0)
#
# Environment:
#   PROFINET_TEST_IFACE    Override interface (same as argument)
#   PROFINET_TEST_STATION  Override expected station name

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

INTERFACE="${1:-${PROFINET_TEST_IFACE:-eth0}}"
STATION_NAME="${PROFINET_TEST_STATION:-test-pn-device}"
CONTAINER_NAME="profinet-test-device"
STARTUP_WAIT=8

export PNET_INTERFACE="${INTERFACE}"
export PROFINET_TEST_IFACE="${INTERFACE}"
export PROFINET_TEST_STATION="${STATION_NAME}"

# --- Cleanup on exit ---
cleanup() {
    echo ""
    echo "==> Stopping container..."
    docker compose -f "${COMPOSE_FILE}" down --timeout 5 2>/dev/null || true
}
trap cleanup EXIT

# --- Preflight checks ---
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (raw sockets require CAP_NET_RAW)"
    exit 1
fi

if ! ip link show "${INTERFACE}" >/dev/null 2>&1; then
    echo "ERROR: Interface '${INTERFACE}' not found"
    echo "Available interfaces:"
    ip -brief link show
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker not found"
    exit 1
fi

# --- Build and start ---
echo "==> Building PROFINET device emulator..."
docker compose -f "${COMPOSE_FILE}" build

echo "==> Starting container (interface=${INTERFACE}, station=${STATION_NAME})..."
docker compose -f "${COMPOSE_FILE}" up -d

echo "==> Waiting ${STARTUP_WAIT}s for device to initialize..."
sleep "${STARTUP_WAIT}"

# Verify container is running
if ! docker inspect -f '{{.State.Running}}' "${CONTAINER_NAME}" 2>/dev/null | grep -q true; then
    echo "ERROR: Container '${CONTAINER_NAME}' is not running"
    echo "Logs:"
    docker logs "${CONTAINER_NAME}" 2>&1 | tail -20
    exit 1
fi

echo "==> Container is running."
echo ""

# --- Run tests ---
echo "==> Running integration tests..."
cd "${PROJECT_DIR}"
pytest tests/integration/ \
    -m integration \
    -v \
    --tb=short \
    -x \
    "$@"

echo ""
echo "==> Integration tests complete."
