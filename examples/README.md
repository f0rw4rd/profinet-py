# PROFINET Examples

## Quick Start

```python
from profinet import scan, ProfinetDevice

# Iterate over all devices on network
for device in scan("eth0"):
    print(f"{device.name} - {device.ip} - {device.mac}")

# Connect by name OR MAC address
dev = ProfinetDevice.discover("my-device", "eth0")
dev = ProfinetDevice.discover("00:0c:29:ab:cd:ef", "eth0")
```

## Environment Variables

All examples support these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PROFINET_IFACE` | `eth0` | Network interface |
| `PROFINET_DEVICE` | `my-device` | Device name or MAC |
| `PROFINET_IP` | `192.168.1.100` | Device IP address |

```bash
# Example usage
export PROFINET_IFACE=enp0s3
export PROFINET_DEVICE=00:0c:29:ab:cd:ef
sudo python3 01_discover_device.py
```

## Permission Requirements

| Operation | Protocol | Root Required |
|-----------|----------|---------------|
| DCP Discovery (`scan()`) | Raw Ethernet | Yes |
| RPC Read/Write | UDP:34964 | No |
| EPM Lookup | UDP:34964 | No |

**Tip:** Run with `sudo` or set capabilities:
```bash
sudo setcap cap_net_raw+ep $(which python3)
```

## Examples

### Discovery & Connection

| File | Description | Root |
|------|-------------|------|
| `00_scan_network.py` | Scan for all devices (simple) | Yes |
| `01_discover_device.py` | Find device by name | Yes |
| `02_discover_by_ip.py` | Find device by IP | Yes |
| `15_direct_rpc_no_root.py` | Connect by IP (no root) | No |

### Device Information

| File | Description | Root |
|------|-------------|------|
| `03_read_im_records.py` | Read all I&M records | Yes* |
| `13_epm_lookup.py` | Query EPM for device info | No |

### Read/Write Operations

| File | Description | Root |
|------|-------------|------|
| `04_write_im_records.py` | Write I&M1 and I&M2 | Yes* |
| `05_write_multiple.py` | Atomic multi-record write | Yes* |
| `11_low_level_rpc.py` | Direct RPC read/write | Yes* |

### Configuration & Diagnosis

| File | Description | Root |
|------|-------------|------|
| `06_module_diff.py` | Check module configuration | Yes* |
| `07_read_diagnosis.py` | Read diagnosis data | Yes* |
| `08_read_alarms.py` | Read alarm notifications | Yes* |
| `09_discover_topology.py` | Discover slots and ports | Yes* |

### Building Blocks

| File | Description | Root |
|------|-------------|------|
| `10_expected_submodule.py` | Build ExpectedSubmodule block | No |
| `12_dcp_discovery.py` | Low-level DCP discovery | Yes |

### Complete Workflows

| File | Description | Root |
|------|-------------|------|
| `14_full_workflow.py` | Complete read/write workflow | Yes* |

*\* Root only needed for initial DCP discovery. Once you have the IP, use `15_direct_rpc_no_root.py` pattern.*

## Typical Usage

```python
from profinet import scan, ProfinetDevice

# Scan and work with each device
for device in scan("eth0"):
    with device:
        im0 = device.read_im0()
        print(f"{device.name}: {im0.order_id}")

# Or connect to specific device by name or MAC
with ProfinetDevice.discover("00:0c:29:ab:cd:ef", "eth0") as dev:
    print(dev.read_im0().serial_number)
```
