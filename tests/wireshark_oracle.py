"""Wireshark (tshark) as a decode oracle for frames the library builds.

The library's own bytes are captured from mocked sockets, wrapped into
Ethernet frames, written to a pcap and dissected by tshark. Assertions then
run against Wireshark's interpretation (packet-dcerpc-pn-io.c, packet-pn-rt.c)
instead of against a second copy of our own struct layouts.

Only reads a pcap file: no root, no interface, no network. Tests that use it
skip when tshark is not installed.
"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess  # nosec B404 - fixed argv, no shell
from pathlib import Path
from typing import Dict, Iterable, List

import pytest

from profinet.rpc import RPC_PORT

TSHARK = shutil.which("tshark")

requires_tshark = pytest.mark.skipif(TSHARK is None, reason="tshark not installed")

CONTROLLER_MAC = bytes.fromhex("020000000001")
DEVICE_MAC = bytes.fromhex("001122334455")
CONTROLLER_IP = bytes([192, 168, 1, 1])
DEVICE_IP = bytes([192, 168, 1, 100])

# Expert info severity (epan/proto.h PI_ERROR)
_PI_ERROR = 0x00800000

_PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _ipv4_checksum(header: bytes) -> int:
    total = sum(struct.unpack(f">{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def wrap_udp(
    payload: bytes,
    sport: int = 49152,
    dport: int = RPC_PORT,
    src_ip: bytes = CONTROLLER_IP,
    dst_ip: bytes = DEVICE_IP,
) -> bytes:
    """Wrap a UDP payload (a DCE/RPC PDU) into an Ethernet/IPv4/UDP frame."""
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = bytearray(
        struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, src_ip, dst_ip)
    )
    ip[10:12] = struct.pack(">H", _ipv4_checksum(bytes(ip)))
    return DEVICE_MAC + CONTROLLER_MAC + b"\x08\x00" + bytes(ip) + udp


def write_pcap(path: Path, frames: Iterable[bytes]) -> Path:
    """Write Ethernet frames to a classic little-endian pcap file."""
    with open(path, "wb") as f:
        f.write(_PCAP_GLOBAL_HEADER)
        for i, frame in enumerate(frames):
            f.write(struct.pack("<IIII", i, 0, len(frame), len(frame)))
            f.write(frame)
    return path


def _run(args: List[str]) -> str:
    assert TSHARK is not None
    result = subprocess.run(  # nosec B603 - fixed argv
        [TSHARK, "-n", *args], capture_output=True, text=True, check=True, timeout=60
    )
    return result.stdout


def dissect(path: Path, fields: Iterable[str]) -> List[Dict[str, List[str]]]:
    """Return per-frame {field: [values]} for the requested tshark fields."""
    args = ["-r", str(path), "-T", "json"]
    for field in fields:
        args += ["-e", field]
    packets = json.loads(_run(args) or "[]")
    return [p["_source"]["layers"] for p in packets]


def expert_errors(path: Path) -> List[str]:
    """Return malformed-packet and error-severity expert messages, if any."""
    out = _run(
        [
            "-r",
            str(path),
            "-T",
            "fields",
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=|",
            "-e",
            "_ws.malformed",
            "-e",
            "_ws.expert.message",
            "-e",
            "_ws.expert.severity",
        ]
    )
    errors = []
    for line in out.splitlines():
        malformed, messages, severities = (line.split("\t") + ["", "", ""])[:3]
        if malformed:
            errors.append(f"malformed: {line}")
        for msg, sev in zip(messages.split("|"), severities.split("|"), strict=False):
            if sev and int(sev, 0) >= _PI_ERROR:
                errors.append(msg)
    return errors


def _to_int(value: str) -> int:
    if value in ("True", "False"):
        return int(value == "True")
    if ":" in value:  # raw bytes of an "@field", e.g. "00:20"
        return int(value.replace(":", ""), 16)
    return int(value, 0)


def ints(layers: Dict[str, List[str]], field: str) -> List[int]:
    """Field values of one frame as ints.

    tshark prints integers as hex or decimal, booleans as True/False and
    ``@field`` raw bytes as colon-separated hex. ``pn_io.artype_req`` is a
    string field, so its value is only reachable as ``@pn_io.artype_req``.
    """
    return [_to_int(v) for v in layers.get(field, [])]


def make_rpccon(**kwargs):
    """RPCCon on a mocked socket. Use inside ``patch("profinet.rpc.socket")``."""
    from profinet.dcp import DCPDeviceDescription
    from profinet.protocol import PNDCPBlock
    from profinet.rpc import RPCCon

    blocks = {
        PNDCPBlock.NAME_OF_STATION: b"oracle-device",
        PNDCPBlock.IP_ADDRESS: DEVICE_IP + bytes([255, 255, 255, 0, 0, 0, 0, 0]),
        PNDCPBlock.DEVICE_ID: bytes([0x00, 0x2A, 0x00, 0x01]),
    }
    return RPCCon(DCPDeviceDescription(DEVICE_MAC, blocks), timeout=0.01, **kwargs)


def capture_requests(rpc, call) -> List[bytes]:
    """Run ``call()`` and return the UDP payloads RPCCon sent.

    The mocked socket never answers, so the call ends in a timeout once the
    request is on the wire; that error is expected and swallowed.
    """
    from profinet.exceptions import RPCError

    sent: List[bytes] = []
    rpc._socket.sendto.side_effect = lambda data, _addr: sent.append(bytes(data))
    rpc._socket.recvfrom.side_effect = TimeoutError
    try:
        call()
    except RPCError:
        pass
    assert sent, "call sent nothing"
    return sent
