# profinet-py

A Python library for PROFINET IO communication, acting as an IO-Controller.

## Features

- **DCP Discovery & Configuration**: Find devices, set IP/name, signal LEDs, factory reset with full SET response validation
- **DCE/RPC Communication**: Establish Application Relationships (AR) and perform acyclic read/write via slot/subslot/index
- **I&M Records**: Read/write Identification & Maintenance data (IM0-IM5)
- **Cyclic I/O**: Real-time periodic data exchange (RT_CLASS_1) with state machine, double-buffered IO, cycle counter tracking, watchdog fault detection, and graceful shutdown
- **Alarm Handling**: Background alarm listener per IEC 61158-6-10
- **Diagnosis Parsing**: Channel, extended channel, and qualified channel diagnosis decoding
- **Vendor Registry**: 2100+ PROFINET vendor IDs with name lookup
- **Declarative Parsing**: Binary protocol parsing via [construct](https://construct.readthedocs.io/) library
- **Cross-Platform**: Linux (AF_PACKET), Windows (Npcap)
- **High-level API**: `ProfinetDevice` class and `scan()` for quick device interaction

## Requirements

- Python 3.10+
- Administrator/root privileges (for raw Ethernet access)
- `construct>=2.10`

### Platform-specific

| Platform | Raw Socket Backend | Extra Software |
|----------|-------------------|----------------|
| **Linux** | AF_PACKET (built-in) | None |
| **Windows** | Npcap (wpcap.dll) | Install [Npcap](https://npcap.com/) with "WinPcap API-compatible Mode" enabled |

## Installation

```bash
pip install profinet-py
```

From source:

```bash
git clone https://github.com/f0rw4rd/profinet-py.git
cd profinet-py
pip install -e ".[dev]"
```

## Usage

```python
import profinet

# Discover all PROFINET devices on the network
for device in profinet.scan("eth0", timeout=5):
    print(f"Found: {device.name} at {device.ip} ({device.mac})")
```

On Windows, use the adapter's friendly name:

```python
for device in profinet.scan("Ethernet 3", timeout=5):
    print(f"Found: {device.name} at {device.ip}")
```

### Low-level DCP + RPC

```python
from profinet.util import ethernet_socket, get_mac
from profinet.dcp import send_discover, read_response
from profinet.rpc import RPCCon

# Create raw socket on interface
sock = ethernet_socket("eth0")
src_mac = get_mac("eth0")

# Discover PROFINET devices
send_discover(sock, src_mac)
responses = read_response(sock, src_mac, timeout_sec=5)

sock.close()
```

### CLI

```bash
# Discover devices
profinet -i eth0 discover

# Read I&M0 from device
profinet -i eth0 read-inm0 device-name

# Read raw record
profinet -i eth0 read device-name --slot 0 --subslot 1 --index 0xAFF0

# Cyclic IO monitoring (default 32ms cycle)
profinet -i eth0 cyclic device-name --gsdml device.xml

# Custom cycle time
profinet -i eth0 cyclic device-name --gsdml device.xml --cycle-ms 16
```

## Support

If you find this project useful, consider supporting development:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/f0rw4rd)

## License

Dual-licensed under [GPL-3.0](LICENSE) and a [commercial license](LICENSE-COMMERCIAL.md).

Free for open source use under GPL-3.0. If you want to use profinet-py in proprietary
products without GPL obligations, a commercial license is available —
see [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) for details.

## References

- [PROFINET Specification](https://www.profibus.com/technology/profinet)
- [Wireshark PROFINET/IO](https://wiki.wireshark.org/PROFINET/IO)
- [construct library](https://construct.readthedocs.io/)
