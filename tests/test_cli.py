"""Tests for the CLI layer.

All network seams (ethernet_socket, get_mac, dcp.*, rpc.*) are mocked;
these tests pin argument parsing, dispatch, output, and exit codes.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import profinet.cli as cli
import profinet.cyclic as cyclic_module
import profinet.gsdml as gsdml_module
from profinet.exceptions import DCPDeviceNotFoundError, PermissionDeniedError, RPCError
from profinet.rpc import IOCRSetup, IOSlot
from profinet.rt import IOCR_TYPE_INPUT, IOCR_TYPE_OUTPUT

CTRL_MAC = b"\x00\x11\x22\x33\x44\x55"
TARGET = "aa:bb:cc:dd:ee:ff"


@pytest.fixture
def net(monkeypatch):
    """Mock the socket layer used by every command."""
    sock = MagicMock()
    monkeypatch.setattr(cli, "ethernet_socket", MagicMock(return_value=sock))
    monkeypatch.setattr(cli, "get_mac", MagicMock(return_value=CTRL_MAC))
    return sock


def run(*argv):
    return cli.main(["-i", "eth0", *argv])


# =============================================================================
# DCP commands
# =============================================================================


class TestDiscover:
    def test_no_devices(self, net, monkeypatch, capsys):
        monkeypatch.setattr(cli.dcp, "send_discover", MagicMock())
        monkeypatch.setattr(cli.dcp, "read_response", MagicMock(return_value={}))
        assert run("discover") == 0
        assert "No devices found" in capsys.readouterr().out

    def test_devices_printed(self, net, monkeypatch, capsys):
        monkeypatch.setattr(cli.dcp, "send_discover", MagicMock())
        monkeypatch.setattr(cli.dcp, "read_response", MagicMock(return_value={b"\x01" * 6: {}}))
        monkeypatch.setattr(cli.dcp, "DCPDeviceDescription", MagicMock(return_value="fake-device"))
        assert run("discover") == 0
        out = capsys.readouterr().out
        assert "Found 1 device(s)" in out
        assert "fake-device" in out

    def test_socket_closed(self, net, monkeypatch):
        monkeypatch.setattr(cli.dcp, "send_discover", MagicMock())
        monkeypatch.setattr(cli.dcp, "read_response", MagicMock(return_value={}))
        run("discover")
        net.close.assert_called_once()


class TestGetParam:
    def test_name(self, net, monkeypatch, capsys):
        monkeypatch.setattr(cli.dcp, "get_param", MagicMock(return_value=b"station-1"))
        assert run("get-param", TARGET, "name") == 0
        assert "station-1" in capsys.readouterr().out

    def test_ip(self, net, monkeypatch, capsys):
        monkeypatch.setattr(
            cli.dcp, "get_param", MagicMock(return_value=b"\xc0\xa8\x00\x0a" + b"\x00" * 8)
        )
        assert run("get-param", TARGET, "ip") == 0
        assert "192.168.0.10" in capsys.readouterr().out

    def test_missing_param_fails(self, net, monkeypatch, capsys):
        monkeypatch.setattr(cli.dcp, "get_param", MagicMock(return_value=None))
        assert run("get-param", TARGET, "name") == 1


class TestSetParam:
    def test_success(self, net, monkeypatch, capsys):
        set_param = MagicMock(return_value=True)
        monkeypatch.setattr(cli.dcp, "set_param", set_param)
        assert run("set-param", TARGET, "name", "new-name") == 0
        assert set_param.call_args.kwargs["permanent"] is False
        assert "Set name = new-name" in capsys.readouterr().out

    def test_permanent_flag_forwarded(self, net, monkeypatch):
        set_param = MagicMock(return_value=True)
        monkeypatch.setattr(cli.dcp, "set_param", set_param)
        assert run("set-param", TARGET, "name", "new-name", "--permanent") == 0
        assert set_param.call_args.kwargs["permanent"] is True

    def test_timeout_fails(self, net, monkeypatch):
        monkeypatch.setattr(cli.dcp, "set_param", MagicMock(return_value=False))
        assert run("set-param", TARGET, "name", "new-name") == 1

    def test_ip_choice_removed(self, net):
        with pytest.raises(SystemExit):
            run("set-param", TARGET, "ip", "10.0.0.1")


class TestSetIp:
    def test_success(self, net, monkeypatch, capsys):
        set_ip = MagicMock(return_value=True)
        monkeypatch.setattr(cli.dcp, "set_ip", set_ip)
        assert run("set-ip", TARGET, "10.0.0.5", "255.255.255.0", "10.0.0.1") == 0
        assert set_ip.call_args.kwargs["permanent"] is False
        assert "Set IP=10.0.0.5" in capsys.readouterr().out

    def test_permanent(self, net, monkeypatch):
        set_ip = MagicMock(return_value=True)
        monkeypatch.setattr(cli.dcp, "set_ip", set_ip)
        run("set-ip", TARGET, "10.0.0.5", "255.255.255.0", "10.0.0.1", "--permanent")
        assert set_ip.call_args.kwargs["permanent"] is True

    def test_timeout_fails(self, net, monkeypatch):
        monkeypatch.setattr(cli.dcp, "set_ip", MagicMock(return_value=False))
        assert run("set-ip", TARGET, "10.0.0.5", "255.255.255.0", "10.0.0.1") == 1


class TestSignal:
    def test_success(self, net, monkeypatch, capsys):
        monkeypatch.setattr(cli.dcp, "signal_device", MagicMock(return_value=True))
        assert run("signal", TARGET) == 0
        assert "flash triggered" in capsys.readouterr().out

    def test_timeout_fails(self, net, monkeypatch):
        monkeypatch.setattr(cli.dcp, "signal_device", MagicMock(return_value=False))
        assert run("signal", TARGET) == 1


class TestReset:
    def test_default_mode_factory(self, net, monkeypatch):
        reset = MagicMock(return_value=True)
        monkeypatch.setattr(cli.dcp, "reset_to_factory", reset)
        assert run("reset", TARGET) == 0
        assert reset.call_args.kwargs["mode"] == cli.RESET_MODES["factory"]

    def test_explicit_mode(self, net, monkeypatch):
        reset = MagicMock(return_value=True)
        monkeypatch.setattr(cli.dcp, "reset_to_factory", reset)
        assert run("reset", TARGET, "--mode", "communication") == 0
        assert reset.call_args.kwargs["mode"] == cli.RESET_MODES["communication"]

    def test_timeout_fails(self, net, monkeypatch):
        monkeypatch.setattr(cli.dcp, "reset_to_factory", MagicMock(return_value=False))
        assert run("reset", TARGET) == 1


# =============================================================================
# RPC commands
# =============================================================================


@pytest.fixture
def rpc_conn(monkeypatch):
    """Mock rpc.get_station_info and RPCCon; returns the connection mock."""
    conn = MagicMock()
    rpccon_cls = MagicMock()
    rpccon_cls.return_value.__enter__ = MagicMock(return_value=conn)
    rpccon_cls.return_value.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr(cli.rpc, "get_station_info", MagicMock(return_value=MagicMock()))
    monkeypatch.setattr(cli.rpc, "RPCCon", rpccon_cls)
    return conn


class TestRead:
    def test_read_hex_index(self, net, rpc_conn, capsys):
        rpc_conn.read.return_value = SimpleNamespace(payload=b"\xde\xad\xbe\xef")
        assert run("read", "dev1", "--slot", "0", "--subslot", "1", "--index", "0xAFF0") == 0
        assert rpc_conn.read.call_args.kwargs["idx"] == 0xAFF0
        out = capsys.readouterr().out
        assert "deadbeef" in out

    def test_read_decimal_index(self, net, rpc_conn):
        rpc_conn.read.return_value = SimpleNamespace(payload=b"")
        assert run("read", "dev1", "--slot", "0", "--subslot", "1", "--index", "123") == 0
        assert rpc_conn.read.call_args.kwargs["idx"] == 123


class TestWrite:
    def test_write_parses_hex_data(self, net, rpc_conn, capsys):
        assert (
            run(
                "write",
                "dev1",
                "--slot",
                "1",
                "--subslot",
                "1",
                "--index",
                "0xAFF1",
                "de ad be ef",
            )
            == 0
        )
        assert rpc_conn.write.call_args.kwargs["data"] == b"\xde\xad\xbe\xef"
        assert "Wrote 4 bytes" in capsys.readouterr().out


class TestReadInm:
    @pytest.mark.parametrize("command", ["read-inm0", "read-inm1", "read-inm2", "read-inm3"])
    def test_inm_printed(self, net, rpc_conn, monkeypatch, capsys, command):
        klass = command.replace("read-inm", "PNInM")
        monkeypatch.setattr(cli, klass, MagicMock(return_value=f"{klass}-data"))
        rpc_conn.read.return_value = SimpleNamespace(payload=b"\x01\x02")
        assert run(command, "dev1") == 0
        assert f"{klass}-data" in capsys.readouterr().out

    @pytest.mark.parametrize("command", ["read-inm0", "read-inm1", "read-inm2", "read-inm3"])
    def test_inm_empty_payload(self, net, rpc_conn, capsys, command):
        rpc_conn.read.return_value = SimpleNamespace(payload=b"")
        assert run(command, "dev1") == 0
        assert "No IM" in capsys.readouterr().out

    def test_inm0_filter_topology(self, net, rpc_conn, capsys):
        rpc_conn.read_inm0filter.return_value = {0: {1: (0x42, {1: 0x99})}}
        assert run("read-inm0-filter", "dev1") == 0
        out = capsys.readouterr().out
        assert "Slot 1: Module 0x0042" in out
        assert "Subslot 1: Submodule 0x0099" in out


# =============================================================================
# main() error handling
# =============================================================================


class TestMainErrorHandling:
    def _fail_with(self, monkeypatch, exc):
        monkeypatch.setattr(cli, "ethernet_socket", MagicMock(side_effect=exc))

    def test_permission_denied(self, monkeypatch, capsys):
        self._fail_with(monkeypatch, PermissionDeniedError("no root"))
        assert run("discover") == 1
        assert "Root privileges" in capsys.readouterr().err

    def test_device_not_found(self, monkeypatch, capsys):
        self._fail_with(monkeypatch, DCPDeviceNotFoundError("gone"))
        assert run("discover") == 1

    def test_rpc_error(self, monkeypatch, capsys):
        self._fail_with(monkeypatch, RPCError("bad response"))
        assert run("discover") == 1
        assert "RPC Error" in capsys.readouterr().err

    def test_keyboard_interrupt(self, monkeypatch, capsys):
        self._fail_with(monkeypatch, KeyboardInterrupt())
        assert run("discover") == 130

    def test_unexpected_error(self, monkeypatch, capsys):
        self._fail_with(monkeypatch, ValueError("boom"))
        assert run("discover") == 1

    def test_missing_interface_exits(self):
        with pytest.raises(SystemExit):
            cli.main(["discover"])

    def test_missing_command_exits(self):
        with pytest.raises(SystemExit):
            cli.main(["-i", "eth0"])


# =============================================================================
# _build_iocr_configs
# =============================================================================


class TestBuildIocrConfigs:
    def test_offsets_and_iocs_only_slots(self):
        slots = [
            IOSlot(
                slot=1,
                subslot=1,
                input_length=4,
                output_length=0,
                module_ident=1,
                submodule_ident=1,
            ),
            IOSlot(
                slot=2,
                subslot=1,
                input_length=2,
                output_length=2,
                module_ident=2,
                submodule_ident=1,
            ),
        ]
        input_iocr, output_iocr = cli._build_iocr_configs(
            slots,
            input_frame_id=0xC001,
            output_frame_id=0x8002,
            send_clock_factor=32,
            reduction_ratio=32,
        )

        assert input_iocr.iocr_type == IOCR_TYPE_INPUT
        assert input_iocr.frame_id == 0xC001
        assert [(o.frame_offset, o.data_length, o.iops_offset) for o in input_iocr.objects] == [
            (0, 4, 4),
            (5, 2, 7),
        ]

        assert output_iocr.iocr_type == IOCR_TYPE_OUTPUT
        # Only slot 2 has output data; slot 1 contributes an IOCS byte
        assert [(o.slot, o.frame_offset) for o in output_iocr.objects] == [(2, 0)]

    def test_minimum_data_length_floor(self):
        slots = [
            IOSlot(
                slot=1,
                subslot=1,
                input_length=1,
                output_length=1,
                module_ident=1,
                submodule_ident=1,
            ),
        ]
        input_iocr, output_iocr = cli._build_iocr_configs(
            slots, 0xC001, 0x8002, send_clock_factor=32, reduction_ratio=32
        )
        assert input_iocr.data_length == 40
        assert output_iocr.data_length == 40


class TestCyclicTopologyPolicy:
    @pytest.mark.parametrize(
        ("exclude_zero_io_submodules", "expected_slots"),
        [
            (False, [(0, 0x8000), (0, 0x8001), (1, 1), (2, 1)]),
            (True, [(1, 1), (2, 1)]),
        ],
    )
    def test_cyclic_uses_one_effective_slot_set_for_setup_and_runtime(
        self, net, monkeypatch, exclude_zero_io_submodules, expected_slots
    ):
        topology_slots = [
            IOSlot(0, 0x8000, 0, 0, module_ident=1, submodule_ident=0x100),
            IOSlot(0, 0x8001, 0, 0, module_ident=1, submodule_ident=0x200),
            IOSlot(1, 1, 24, 0, module_ident=2, submodule_ident=1),
            IOSlot(2, 1, 0, 32, module_ident=3, submodule_ident=1),
        ]
        gsdml_device = MagicMock()
        gsdml_device.build_io_slots_from_device.return_value = topology_slots
        monkeypatch.setattr(gsdml_module, "load_gsdml", MagicMock(return_value=gsdml_device))

        info = SimpleNamespace(ip="192.168.0.10", mac="02:00:00:00:00:01")
        monkeypatch.setattr(cli.rpc, "get_station_info", MagicMock(return_value=info))
        conn = MagicMock()
        conn.discover_slots.return_value = topology_slots
        conn._socket.recvfrom.side_effect = TimeoutError
        conn.connect.side_effect = [
            None,
            SimpleNamespace(has_cyclic=True, input_frame_id=0xC001, output_frame_id=0x8002),
        ]
        monkeypatch.setattr(cli.rpc, "RPCCon", MagicMock(return_value=conn))

        cyclic = MagicMock()
        monkeypatch.setattr(cyclic_module, "CyclicController", cyclic)
        build_configs = MagicMock(wraps=cli._build_iocr_configs)
        monkeypatch.setattr(cli, "_build_iocr_configs", build_configs)
        monotonic = iter((0.0, 1.1))
        monkeypatch.setattr(cli.time, "monotonic", lambda: next(monotonic))
        monkeypatch.setattr(cli.time, "sleep", lambda _seconds: None)

        args = SimpleNamespace(
            interface="eth0",
            target="anybus-inarco",
            gsdml="device.gsdml",
            submodule=None,
            cycle_ms=32,
            duration=1,
            exclude_zero_io_submodules=exclude_zero_io_submodules,
        )

        assert cli.cmd_cyclic(args) == 0
        assert len(topology_slots) == 4

        setup = conn.connect.call_args_list[1].kwargs["iocr_setup"]
        assert setup.slots is not topology_slots
        assert [(slot.slot, slot.subslot) for slot in setup.slots] == expected_slots
        assert build_configs.call_args.args[0] is setup.slots

        input_iocr, output_iocr = (
            cyclic.call_args.kwargs["input_iocr"],
            cyclic.call_args.kwargs["output_iocr"],
        )
        assert [(obj.slot, obj.subslot) for obj in input_iocr.objects] == [(1, 1)]
        assert [(obj.slot, obj.subslot) for obj in output_iocr.objects] == [(2, 1)]

    def test_library_policy_defaults_to_complete_topology(self):
        slots = [IOSlot(0, 0x8000), IOSlot(1, 1, input_length=8)]

        setup = IOCRSetup(slots=slots)

        assert [(slot.slot, slot.subslot) for slot in setup.slots] == [(0, 0x8000), (1, 1)]
        assert setup.slots is not slots

    def test_library_policy_excludes_only_zero_io_submodules_when_enabled(self):
        slots = [
            IOSlot(0, 0x8000),
            IOSlot(1, 1, input_length=8),
            IOSlot(2, 1, output_length=4),
        ]

        setup = IOCRSetup(slots=slots, exclude_zero_io_submodules=True)

        assert [(slot.slot, slot.subslot) for slot in setup.slots] == [(1, 1), (2, 1)]

    def test_cyclic_flag_is_opt_in(self):
        parser = cli.create_parser()

        default_args = parser.parse_args(["-i", "eth0", "cyclic", "dev", "--gsdml", "x.xml"])
        opted_in_args = parser.parse_args(
            [
                "-i",
                "eth0",
                "cyclic",
                "dev",
                "--gsdml",
                "x.xml",
                "--exclude-zero-io-submodules",
            ]
        )

        assert default_args.exclude_zero_io_submodules is False
        assert opted_in_args.exclude_zero_io_submodules is True
