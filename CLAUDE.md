# CLAUDE.md

This file provides guidance to Claude Code and other AI coding assistants when
working in this repository.

## Project overview

`profinet-py` is a pure-Python PROFINET IO-Controller library: DCP discovery
and configuration, DCE/RPC record read/write (including I&M0 to I&M5),
diagnosis and alarm parsing, and RT_CLASS_1 cyclic IO. It ships a `profinet`
console script (`profinet.cli:main`).

The package supports Python 3.10 and newer (`requires-python = ">=3.10"`; CI
tests 3.10 to 3.14). `construct>=2.10` is its only runtime dependency. Linux is
the primary platform (AF_PACKET raw sockets); `profinet/util.py` also has a
Windows path through Npcap (`wpcap.dll` via ctypes).

Layer 2 operations (DCP, RT frames, discovery behind `ProfinetDevice`) need raw
sockets, so root or `CAP_NET_RAW` on Linux. Pure UDP paths such as
`epm_lookup()` work without root (`examples/15_direct_rpc_no_root.py`).

This is an unofficial implementation. Anything involving a real device (DCP
set/reset, record writes, cyclic outputs) must be tested only against an
isolated, non-safety-critical device on a dedicated interface.

## Repository layout

- `profinet/__init__.py`: public exports and `__version__`, the single source of
  the package version (read by `[tool.setuptools.dynamic]` and checked against
  the tag in `release.yml`)
- `profinet/device.py`: high-level API: `ProfinetDevice`, `DeviceInfo`,
  `WriteItem`, `scan`, `scan_dict`
- `profinet/dcp.py`: DCP identify/get/set/hello, `set_ip`, `signal_device`,
  `reset_to_factory`, DCP option/suboption/error constants
- `profinet/rpc.py`: DCE/RPC client `RPCCon` (AR connect, read, write, Read
  Implicit, IOCR setup), `get_station_info`, `epm_lookup`, RPC constants and
  UUIDs
- `profinet/protocol.py`: packet definitions (Ethernet, DCP, RPC, IOD headers,
  I&M0 to I&M5) built with `make_packet()`
- `profinet/util.py`: `make_packet()` (construct-backed packet factory), raw
  Ethernet and UDP socket helpers (AF_PACKET and Npcap), MAC/IP helpers
- `profinet/blocks.py`: block parsing (block header, PDRealData,
  RealIdentificationData, port statistics, ModuleDiff, WriteMultiple,
  ExpectedSubmodule)
- `profinet/diagnosis.py`: channel, extended channel and qualified channel
  diagnosis parsing and error-type decoding
- `profinet/alarms.py`: AlarmNotification and alarm item parsing
- `profinet/alarm_listener.py`: background alarm reception (`AlarmListener`,
  `AlarmEndpoint`) over raw Ethernet or UDP port 34964
- `profinet/rt.py`: RT_CLASS_1 frame building/parsing, `IOCRConfig`,
  `CyclicDataBuilder`
- `profinet/cyclic.py`: `CyclicController` for periodic output and input frame
  exchange
- `profinet/gsdml.py`: GSDML XML parser that builds IOSlot lists for cyclic IO
- `profinet/indices.py`: record index constants (I&M, diagnosis, port, etc.)
- `profinet/vendors.py`: PI vendor ID table (registry version noted in the
  module docstring)
- `profinet/exceptions.py`: exception hierarchy rooted at `ProfinetError`
- `profinet/cli.py`: argparse CLI (`discover`, `get-param`, `set-param`,
  `read`, `write`, `read-inm0` to `read-inm3`, `read-inm0-filter`, `set-ip`,
  `signal`, `reset`, `cyclic`)
- `tests/`: unit tests (`tests/test_*.py`) and `tests/integration/`, which runs
  against a p-net based device emulator in Docker (`docker-compose.yml`,
  `docker/`, `run.sh`)
- `examples/`: numbered example scripts `00` to `18` plus `examples/README.md`
- `tools/hw_cyclic_check.py`: manual cyclic IO bring-up against a physical
  device; not a pytest module
- `vulture_whitelist.py`: vulture false-positive whitelist

`reference/` exists locally but is gitignored and not part of the repository;
do not assume it exists in other checkouts and never import from it.

Package data: `pyproject.toml` has no explicit package-data table; packages are
found with `include = ["profinet*"]`, and `profinet/py.typed` ships in the
wheel. Keep `py.typed` in place.

## Protocol stack and design constraints

The library speaks four paths, and each has its own framing:

- DCP: raw Ethernet, EtherType 0x8892, multicast identify plus unicast get/set
  and hello.
- RT cyclic frames (RT_CLASS_1): raw Ethernet, EtherType 0x8892, frame ID plus
  IO data with IOPS/IOCS and a cycle counter, data status and transfer status
  trailer.
- Acyclic records: DCE/RPC over UDP (port 34964, `RPC_PORT`), with EPM lookup,
  AR connect/release, record read/write and Read Implicit.
- Alarms: AlarmNotification PDUs received on raw Ethernet or UDP.

Protocol parsing must treat device data as untrusted:

- Validate lengths, offsets, block types and block header lengths before
  slicing; a truncated or oversized block must raise, not read past the buffer
  or loop forever.
- Use `make_packet()` and the construct-based parsers already present for new
  structures instead of ad-hoc slicing.
- Raise exceptions from `profinet/exceptions.py` (`DCPError`, `RPCError`,
  `PNIOError`, `ValidationError`, `SocketError` and their subclasses), not bare
  `Exception` or `ValueError`.
- Use the module `logger = logging.getLogger(__name__)`, not `print()`, for
  library diagnostics (`print` belongs only in `cli.py` and examples).
- Never weaken defaults (timeouts, XID checking, validation) merely to make a
  test or a quirky device pass; add an opt-in parameter instead, as
  `strict_xid` does.

Keep socket mechanics in `util.py`, wire structures in `protocol.py` and the
parsing modules, and user-facing operations in `device.py`.

## Public API

The main entry points are `ProfinetDevice`, `scan` and `scan_dict` from
`profinet`. `profinet/__init__.py` also exports the DCP functions and constants,
`RPCCon`, `epm_lookup`, the block, diagnosis, alarm, RT/cyclic and GSDML types,
the protocol structures, utilities and the exception hierarchy. Update both the
import list and `__all__` deliberately when adding public API.

```python
from profinet import ProfinetDevice, scan

for dev in scan(interface="eth0", timeout=3.0):
    print(dev.name, dev.ip)

with ProfinetDevice.discover("my-device", "eth0") as device:
    im0 = device.read_im0()
    raw = device.read(slot=0, subslot=1, index=0xAFF0)
```

`ProfinetDevice.from_ip(ip, interface)` discovers by IP instead of station
name. `discover()` also accepts a MAC address as the identifier.

## Development setup and checks

Install the project and development tools, and enable the hooks:

```bash
pip install -e ".[dev]"
pre-commit install --hook-type pre-commit --hook-type pre-push --hook-type commit-msg
```

Checks, as run by `.github/workflows/ci.yml` and `.pre-commit-config.yaml`:

```bash
ruff check profinet/
ruff format --check profinet/
vulture profinet/ vulture_whitelist.py
bandit -c pyproject.toml -r profinet/
pytest -v
pytest --collect-only -q
```

Pre-commit runs ruff check `--fix`, ruff format and vulture on commit; bandit
and `python -m pytest tests/ -x -q` on push; `.githooks/no-ai-coauthor` on
commit-msg. On pull requests, `auto-format.yml` runs `ruff format profinet/`
and pushes the result to the branch.

Ruff targets Python 3.10 with line length 100. Vulture uses
`min_confidence = 80`; bandit skips B101. MyPy is not configured or run
anywhere; do not claim a mypy check passed.

Integration tests are marked `integration` and deselected by default
(`addopts = "-m 'not integration'"`). They need root and the Docker emulator:

```bash
sudo ./tests/integration/run.sh [INTERFACE]
# or: docker compose -f tests/integration/docker-compose.yml up --build -d
#     sudo pytest tests/integration/ -m integration -v
```

`PROFINET_TEST_IFACE` and `PROFINET_TEST_STATION` override the interface and
station name. Real hardware is only exercised by hand via
`tools/hw_cyclic_check.py` (`PROFINET_IFACE`, `PROFINET_NAME`).

Release: push a tag `vX.Y.Z` matching `profinet.__version__`. `release.yml`
reruns CI, builds sdist and wheel, runs `twine check`, attests provenance,
publishes to PyPI through OIDC trusted publishing (`pypi` environment) and
creates a GitHub Release with `SHA256SUMS.txt`. `workflow_dispatch` with
`dry_run` builds without publishing.

## Testing expectations

- Add byte-exact tests for new builders and parsers (DCP blocks, RPC/IOD
  headers, RT frames, alarm and diagnosis blocks), using vectors from a capture
  or the Wireshark dissector.
- Add malformed and truncated input cases for every parser, including bad block
  lengths and short frames.
- Bug fixes include a regression test that fails without the fix.
- Unit tests must not need root, a network interface or Docker; mock sockets
  instead. Anything that needs them goes under `tests/integration/` with the
  `integration` marker, and physical hardware stays opt-in in `tools/`.
- Do not turn an integration failure into a unit-test skip; reproduce with the
  emulator or captured bytes.

## Code quality and contribution rules

- Give a checkable source for every new frame ID, block type, index, error
  code, enum value or vendor entry (a capture, the Wireshark `pn_io`/`pn_dcp`
  dissector table, IEC 61158-6-10, or the file and line that really lists it),
  and say when a value is unverified or seen on only one device and firmware.
- Prefer small, focused changes with one coherent purpose per pull request.
- Conventional commits, lowercase after the colon. No AI co-author lines:
  `.githooks/no-ai-coauthor` rejects `Co-Authored-By` lines naming Claude or
  Anthropic (see also `CONTRIBUTING.md`).
- There is no `CHANGES.md`; release notes are generated by the GitHub Release.
- Update `README.md`, `__all__` and the exports, `examples/` and tests when a
  public API, CLI command or supported-platform claim changes.
- Keep `vulture_whitelist.py` minimal; remove dead code rather than whitelisting
  it.
