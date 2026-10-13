from unittest.mock import MagicMock, call, patch

from profinet.dcp import DCPDeviceDescription
from profinet.rpc import ConnectResult, IOCRSetup
from profinet.system_redundancy import PLC, SystemRedundancy


def make_system_redundancy(rpc_instances=None, **options):
    info = DCPDeviceDescription(b"\x00\x11\x22\x33\x44\x55", {})
    info.ip = "192.0.2.10"
    info.netmask = "255.255.255.0"
    primary_ip = options.pop("primary_ip", "192.0.2.1")
    secondary_ip = options.pop("secondary_ip", "192.0.2.2")
    with patch("profinet.system_redundancy.RPCCon", side_effect=rpc_instances):
        return SystemRedundancy(
            info=info,
            interface="test0",
            primary_ip=primary_ip,
            secondary_ip=secondary_ip,
            src_mac=b"\x00\x11\x22\x33\x44\x66",
            iocr_setup=IOCRSetup(slots=[]),
            **options,
        )


def test_plc_ips_must_match_device_subnet():
    with patch("profinet.system_redundancy.RPCCon") as rpc_con:
        try:
            make_system_redundancy(
                [],
                primary_ip="192.0.3.1",
                secondary_ip="192.0.2.2",
            )
        except ValueError as error:
            assert "PLC A IP 192.0.3.1" in str(error)
            assert "192.0.2.0/24" in str(error)
        else:
            raise AssertionError("PLC IP outside the device subnet must be rejected")

        rpc_con.assert_not_called()


def test_secondary_plc_ip_must_match_device_subnet():
    with patch("profinet.system_redundancy.RPCCon") as rpc_con:
        try:
            make_system_redundancy(
                [],
                primary_ip="192.0.2.1",
                secondary_ip="192.0.3.2",
            )
        except ValueError as error:
            assert "PLC B IP 192.0.3.2" in str(error)
        else:
            raise AssertionError("PLC IP outside the device subnet must be rejected")

        rpc_con.assert_not_called()


def test_plc_resources_are_grouped_per_connection():
    first_rpc = MagicMock()
    second_rpc = MagicMock()
    system = make_system_redundancy([first_rpc, second_rpc])

    first = system.plcs[PLC.A]
    second = system.plcs[PLC.B]
    assert first.rpc is first_rpc
    assert second.rpc is second_rpc
    assert first.rpc is not second.rpc
    assert first.local_ip == "192.0.2.1"
    assert second.local_ip == "192.0.2.2"
    assert first.interface == second.interface == "test0"
    assert first.src_mac == second.src_mac == b"\x00\x11\x22\x33\x44\x66"
    assert first.sr_info.ar_number == 1
    assert second.sr_info.ar_number == 2
    assert first.cyclic is None and first.alarm_listener is None
    assert second.cyclic is None and second.alarm_listener is None


def test_connect_only_populates_selected_ar():
    first_rpc = MagicMock()
    second_rpc = MagicMock()
    first_rpc._alarm_cr_enabled = False
    result = ConnectResult(input_frame_id=0xC001, output_frame_id=0xC000)
    first_rpc.connect.return_value = result
    system = make_system_redundancy([first_rpc, second_rpc])
    cyclic = MagicMock()

    with (
        patch("profinet.system_redundancy.build_iocr_configs", return_value=(object(), object())),
        patch("profinet.system_redundancy.CyclicController", return_value=cyclic),
    ):
        assert system.connect(plc=PLC.A) is result

    first_rpc.connect.assert_called_once()
    second_rpc.connect.assert_not_called()
    assert system.plcs[PLC.A].result is result
    assert system.plcs[PLC.A].cyclic is cyclic
    assert system.plcs[PLC.B].result is None
    assert system.plcs[PLC.B].cyclic is None


def test_reconnect_discards_dropped_ar_and_restarts_as_backup():
    rpc = MagicMock()
    rpc._alarm_cr_enabled = False
    rpc.connect.return_value = ConnectResult(input_frame_id=0xC001, output_frame_id=0xC000)
    system = make_system_redundancy([rpc, MagicMock()])
    old_cyclic = MagicMock()
    new_cyclic = MagicMock()
    connection = system.plcs[PLC.A]
    connection.cyclic = old_cyclic
    connection.initial_prm_end_done = True
    connection.initial_application_ready = True
    system._device_parameterized = True

    with (
        patch("profinet.system_redundancy.build_iocr_configs", return_value=(object(), object())),
        patch("profinet.system_redundancy.CyclicController", return_value=new_cyclic) as make,
    ):
        system.connect(plc=PLC.A)

    old_cyclic.stop.assert_called_once_with(send_stop_frames=False)
    assert make.call_args.kwargs["primary"] is False
    assert connection.cyclic is new_cyclic
    assert not connection.initial_prm_end_done
    assert not connection.initial_application_ready
    assert not system._device_parameterized


def test_prm_end_forwards_write_multiple_option_to_selected_plc():
    first_rpc = MagicMock()
    second_rpc = MagicMock()
    first_rpc.prm_end.return_value = b"response"
    system = make_system_redundancy([first_rpc, second_rpc])

    result = system.prm_end(
        plc=PLC.A,
        send_startup_parameters=True,
        use_write_multiple=False,
    )

    assert result == b"response"
    first_rpc.prm_end.assert_called_once_with(
        send_startup_parameters=True,
        use_write_multiple=False,
    )
    second_rpc.prm_end.assert_not_called()


def test_start_selects_only_requested_ar():
    system = make_system_redundancy([MagicMock(), MagicMock()])
    first_cyclic = MagicMock()
    second_cyclic = MagicMock()
    system.plcs[PLC.A].cyclic = first_cyclic
    system.plcs[PLC.B].cyclic = second_cyclic

    system.start(plc=PLC.B)

    first_cyclic.start.assert_not_called()
    second_cyclic.start.assert_called_once_with()


def test_io_updates_are_applied_to_both_existing_ars():
    system = make_system_redundancy([MagicMock(), MagicMock()])
    first_cyclic = MagicMock()
    second_cyclic = MagicMock()
    system.plcs[PLC.A].cyclic = first_cyclic
    system.plcs[PLC.B].cyclic = second_cyclic

    system.update_io_status(1, 4, 0x00)
    system.update_io(1, 4, b"same")

    for cyclic in (first_cyclic, second_cyclic):
        cyclic.set_output_status.assert_called_once_with(1, 4, 0x00)
        cyclic.set_output_data.assert_called_once_with(1, 4, b"same")


def test_io_updates_are_replayed_to_ars_connected_later():
    first_rpc = MagicMock()
    second_rpc = MagicMock()
    first_rpc._alarm_cr_enabled = False
    second_rpc._alarm_cr_enabled = False
    first_rpc.connect.return_value = ConnectResult(input_frame_id=0xC001, output_frame_id=0xC000)
    second_rpc.connect.return_value = ConnectResult(input_frame_id=0xC002, output_frame_id=0xC003)
    system = make_system_redundancy([first_rpc, second_rpc])
    first_cyclic = MagicMock()
    second_cyclic = MagicMock()
    system.update_io_status(1, 4, 0x00)
    system.update_io(1, 4, b"same")

    with (
        patch("profinet.system_redundancy.build_iocr_configs", return_value=(object(), object())),
        patch(
            "profinet.system_redundancy.CyclicController",
            side_effect=[first_cyclic, second_cyclic],
        ),
    ):
        system.connect(plc=PLC.A)
        system.connect(plc=PLC.B)

    for cyclic in (first_cyclic, second_cyclic):
        cyclic.set_output_data.assert_called_once_with(1, 4, b"same")
        cyclic.set_output_status.assert_called_once_with(1, 4, 0x00)


def test_startup_parameters_register_for_both_ars_or_selected_ar():
    first_rpc = MagicMock()
    second_rpc = MagicMock()
    system = make_system_redundancy([first_rpc, second_rpc])

    system.add_startup_parameter(3, 4, 5, 6, b"shared")
    system.add_startup_parameter(7, 8, 9, 10, b"second-only", plc=PLC.B)

    assert first_rpc.add_startup_parameter.call_args_list == [call(3, 4, 5, 6, b"shared")]
    assert second_rpc.add_startup_parameter.call_args_list == [
        call(3, 4, 5, 6, b"shared"),
        call(7, 8, 9, 10, b"second-only"),
    ]


def test_distinct_interfaces_use_each_interface_mac_for_its_ar():
    first_rpc = MagicMock()
    second_rpc = MagicMock()
    second_rpc._alarm_cr_enabled = False
    second_rpc.connect.return_value = ConnectResult(input_frame_id=0xC001, output_frame_id=0xC000)
    second_mac = b"\x00\x11\x22\x33\x44\x77"
    system = make_system_redundancy(
        [first_rpc, second_rpc],
        secondary_interface="test1",
        secondary_src_mac=second_mac,
    )

    cyclic = MagicMock()
    with (
        patch("profinet.system_redundancy.build_iocr_configs", return_value=(object(), object())),
        patch("profinet.system_redundancy.CyclicController", return_value=cyclic) as make_cyclic,
    ):
        system.connect(plc=PLC.B)

    ar2 = system.plcs[PLC.B]
    assert ar2.interface == "test1"
    assert ar2.src_mac == second_mac
    second_rpc.connect.assert_called_once()
    assert second_rpc.connect.call_args.kwargs["src_mac"] == second_mac
    assert make_cyclic.call_args.kwargs["interface"] == "test1"
    assert make_cyclic.call_args.kwargs["src_mac"] == second_mac


def test_distinct_interface_mac_is_detected_when_not_provided():
    first_rpc = MagicMock()
    second_rpc = MagicMock()
    second_mac = b"\x00\x11\x22\x33\x44\x77"
    with patch("profinet.system_redundancy.get_mac", return_value=second_mac) as get_mac:
        system = make_system_redundancy([first_rpc, second_rpc], secondary_interface="test1")

    get_mac.assert_called_once_with("test1")
    assert system.plcs[PLC.A].interface == "test0"
    assert system.plcs[PLC.A].src_mac == b"\x00\x11\x22\x33\x44\x66"
    assert system.plcs[PLC.B].interface == "test1"
    assert system.plcs[PLC.B].src_mac == second_mac


def test_first_primary_parameterization_switchover_precedes_prm_begin():
    system = make_system_redundancy([MagicMock(), MagicMock()])
    primary_cyclic = MagicMock()
    primary_cyclic.is_primary = False
    primary_cyclic.is_running = True
    system.plcs[PLC.A].cyclic = primary_cyclic
    events = []
    with (
        patch.object(
            system,
            "prm_end",
            side_effect=lambda **kwargs: events.append(
                ("prm_end", kwargs["plc"], kwargs["send_startup_parameters"])
            ),
        ) as prm_end,
        patch.object(
            system,
            "application_ready",
            side_effect=lambda **kwargs: events.append(("app_ready", kwargs["plc"])),
        ) as application_ready,
        patch.object(
            system,
            "wait_for_slave_primary",
            side_effect=lambda **kwargs: events.append(("wait_primary", kwargs["plc"])),
        ),
        patch.object(
            system,
            "prm_begin",
            side_effect=lambda **kwargs: events.append(("prm_begin", kwargs["plc"])),
        ),
        patch.object(
            system,
            "switchover",
            side_effect=lambda **kwargs: events.append(("switchover", kwargs["target"])),
        ) as switchover,
    ):
        system.parameterize(plc=PLC.A)

    assert events == [
        ("prm_end", PLC.A, True),
        ("app_ready", PLC.A),
        ("switchover", PLC.A),
        ("wait_primary", PLC.A),
        ("prm_begin", PLC.A),
        ("prm_end", PLC.A, True),
        ("app_ready", PLC.A),
    ]
    switchover.assert_called_once_with(target=PLC.A, wait_for_ack=True)
    assert prm_end.call_count == 2
    assert application_ready.call_count == 2
    assert system._device_parameterized

    backup_cyclic = MagicMock()
    backup_cyclic.is_running = True
    system.plcs[PLC.B].cyclic = backup_cyclic
    events = []
    with (
        patch.object(
            system,
            "prm_end",
            side_effect=lambda **kwargs: events.append(("prm_end", kwargs["plc"])),
        ),
        patch.object(
            system,
            "application_ready",
            side_effect=lambda **kwargs: events.append(("app_ready", kwargs["plc"])),
        ),
        patch.object(system, "switchover") as switchover,
        patch.object(system, "reparameterize") as reparameterize,
    ):
        system.parameterize(plc=PLC.B, confirm_app_ready=True)
    assert events == [("prm_end", PLC.B), ("app_ready", PLC.B)]
    switchover.assert_not_called()
    reparameterize.assert_not_called()


def test_backup_waits_for_online_preferred_primary_before_initial_setup():
    system = make_system_redundancy([MagicMock(), MagicMock()])
    backup_cyclic = MagicMock()
    backup_cyclic.is_running = True
    system.plcs[PLC.B].cyclic = backup_cyclic
    events = []

    with (
        patch.object(
            system,
            "prm_end",
            side_effect=lambda **kwargs: events.append(("prm_end", kwargs["plc"])),
        ),
        patch.object(
            system,
            "application_ready",
            side_effect=lambda **kwargs: events.append(("app_ready", kwargs["plc"])),
        ),
        patch.object(system, "switchover") as switchover,
        patch.object(system, "reparameterize") as reparameterize,
    ):
        system.parameterize(plc=PLC.B, confirm_app_ready=True)

    assert events == [("prm_end", PLC.B), ("app_ready", PLC.B)]
    switchover.assert_not_called()
    reparameterize.assert_not_called()
    assert not system._device_parameterized

    primary_cyclic = MagicMock()
    primary_cyclic.is_primary = False
    primary_cyclic.is_running = True
    system.plcs[PLC.A].cyclic = primary_cyclic
    events.clear()
    with (
        patch.object(
            system,
            "prm_end",
            side_effect=lambda **kwargs: events.append(("prm_end", kwargs["plc"])),
        ),
        patch.object(
            system,
            "application_ready",
            side_effect=lambda **kwargs: events.append(("app_ready", kwargs["plc"])),
        ),
        patch.object(
            system,
            "wait_for_slave_primary",
            side_effect=lambda **kwargs: events.append(("wait_primary", kwargs["plc"])),
        ),
        patch.object(
            system,
            "prm_begin",
            side_effect=lambda **kwargs: events.append(("prm_begin", kwargs["plc"])),
        ),
        patch.object(system, "switchover") as switchover,
    ):
        system.parameterize(plc=PLC.A, confirm_app_ready=True)

    assert events == [
        ("prm_end", PLC.A),
        ("app_ready", PLC.A),
        ("wait_primary", PLC.A),
        ("prm_begin", PLC.A),
        ("prm_end", PLC.A),
        ("app_ready", PLC.A),
    ]
    switchover.assert_called_once_with(target=PLC.A, wait_for_ack=True)
    assert system._device_parameterized


def test_backup_is_promoted_when_preferred_primary_is_offline():
    system = make_system_redundancy([MagicMock()], online_plcs={PLC.B})
    backup_cyclic = MagicMock()
    backup_cyclic.is_primary = False
    backup_cyclic.is_running = True
    system.plcs[PLC.B].cyclic = backup_cyclic

    with (
        patch.object(system, "switchover") as switchover,
        patch.object(system, "reparameterize") as reparameterize,
    ):
        system.parameterize(plc=PLC.B, confirm_app_ready=True)

    switchover.assert_called_once_with(target=PLC.B, wait_for_ack=True)
    reparameterize.assert_called_once_with(
        plc=PLC.B,
        confirm_app_ready=True,
        app_ready_timeout=30.0,
        wait_for_primary=True,
        primary_timeout=30.0,
        send_startup_parameters=True,
        use_write_multiple=True,
    )
    assert system._device_parameterized

    primary_rpc = MagicMock()
    primary_cyclic = MagicMock()
    primary_cyclic.is_primary = False
    primary_cyclic.is_running = True
    with patch.object(system, "_create_rpc", return_value=primary_rpc):
        system.set_online(PLC.A, True)
    system.plcs[PLC.A].cyclic = primary_cyclic

    with (
        patch.object(system, "switchover") as switchover,
        patch.object(system, "reparameterize") as reparameterize,
    ):
        system.parameterize(plc=PLC.A, confirm_app_ready=True)

    switchover.assert_not_called()
    reparameterize.assert_not_called()
    assert not primary_cyclic.is_primary


def test_offlining_one_plc_keeps_device_parameterized_and_skips_reparameterize():
    rpc_a = MagicMock()
    rpc_b = MagicMock()
    system = make_system_redundancy([rpc_a, rpc_b])
    system._device_parameterized = True
    system.plcs[PLC.B].cyclic = MagicMock()
    system.plcs[PLC.B].cyclic.is_running = True
    system.plcs[PLC.B].cyclic.is_primary = False
    system.switchover = MagicMock()
    system.reparameterize = MagicMock()

    system.set_online(PLC.A, False)

    assert system._device_parameterized
    system.switchover.assert_called_once_with(target=PLC.B, wait_for_ack=True)
    system.reparameterize.assert_not_called()

    system.set_online(PLC.B, False)
    assert not system._device_parameterized


def test_parameterization_resets_when_last_established_ar_is_offline():
    system = make_system_redundancy([MagicMock(), MagicMock()])
    system._device_parameterized = True
    system.plcs[PLC.B].cyclic = MagicMock()

    system.set_online(PLC.B, False)

    assert system.plcs[PLC.A].online
    assert system.plcs[PLC.A].cyclic is None
    assert not system._device_parameterized


def test_reparameterize_runs_control_sequence_without_parameterize_recursion():
    system = make_system_redundancy([MagicMock(), MagicMock()])
    events = []
    system.wait_for_slave_primary = lambda **kwargs: events.append(("wait_primary", kwargs["plc"]))
    system.prm_begin = lambda **kwargs: events.append(("prm_begin", kwargs["plc"]))
    system.prm_end = lambda **kwargs: events.append(
        (
            "prm_end",
            kwargs["plc"],
            kwargs["send_startup_parameters"],
            kwargs["use_write_multiple"],
        )
    )
    system.application_ready = lambda **kwargs: events.append(("app_ready", kwargs["plc"]))

    system.reparameterize(plc=PLC.B, send_startup_parameters=False)

    assert events == [
        ("wait_primary", PLC.B),
        ("prm_begin", PLC.B),
        ("prm_end", PLC.B, False, True),
        ("app_ready", PLC.B),
    ]


def test_initially_offline_plc_does_not_open_rpc_socket():
    rpc_a = MagicMock()
    system = make_system_redundancy([rpc_a], online_plcs={PLC.A})

    assert system.plcs[PLC.A].online
    assert system.plcs[PLC.A].rpc is rpc_a
    assert not system.plcs[PLC.B].online
    assert system.plcs[PLC.B].rpc is None
    assert rpc_a is system.plcs[PLC.A].rpc


def test_plc_selectors_reject_strings():
    system = make_system_redundancy([MagicMock(), MagicMock()])

    with patch("profinet.system_redundancy.RPCCon"):
        try:
            make_system_redundancy([], online_plcs={"A"})
        except TypeError as error:
            assert "online_plcs" in str(error)
        else:
            raise AssertionError("string PLC selectors must be rejected")

    try:
        system.start(plc="A")
    except TypeError as error:
        assert "PLC.A or PLC.B" in str(error)
    else:
        raise AssertionError("string PLC selectors must be rejected")


def test_offline_stops_without_stop_or_release_frames():
    rpc_a = MagicMock()
    rpc_b = MagicMock()
    system = make_system_redundancy([rpc_a, rpc_b])
    cyclic_a = MagicMock()
    alarm_listener = MagicMock()
    system.plcs[PLC.A].cyclic = cyclic_a
    system.plcs[PLC.A].alarm_listener = alarm_listener

    system.set_online(PLC.A, False)

    cyclic_a.stop.assert_called_once_with(send_stop_frames=False)
    rpc_a.close.assert_called_once_with(send_release=False)
    rpc_a.disconnect.assert_not_called()
    alarm_listener.stop.assert_called_once_with()
    assert not system.plcs[PLC.A].online
    assert system.plcs[PLC.A].rpc is None
    assert system.plcs[PLC.A].cyclic is None


def test_offline_can_wait_for_slave_timeout_before_stopping_alarm_listener():
    rpc_a = MagicMock()
    rpc_b = MagicMock()
    system = make_system_redundancy([rpc_a, rpc_b])
    cyclic = MagicMock()
    listener = MagicMock()
    listener.is_running = True
    events = []
    registered_callbacks = []
    listener.add_rta_error_callback.side_effect = registered_callbacks.append
    listener.remove_rta_error_callback.side_effect = lambda callback: events.append(
        "remove_callback"
    )
    listener.stop.side_effect = lambda: events.append("stop_listener")
    cyclic.stop.side_effect = lambda **kwargs: events.append("stop_cyclic")
    system.plcs[PLC.A].cyclic = cyclic
    system.plcs[PLC.A].alarm_listener = listener
    survivor_cyclic = MagicMock()
    survivor_cyclic.is_running = True
    survivor_cyclic.is_primary = False
    system.plcs[PLC.B].cyclic = survivor_cyclic
    system._device_parameterized = True

    class AlarmWait:
        def set(self):
            pass

        def wait(self):
            events.append("wait_for_timeout_alarm")
            registered_callbacks[0](5)

    with (
        patch.object(
            system,
            "switchover",
            side_effect=lambda **kwargs: events.append("switchover"),
        ) as switchover,
        patch("profinet.system_redundancy.threading.Event", return_value=AlarmWait()),
    ):
        system.set_online(PLC.A, False, wait_for_slave_timeout=True)

    assert events == [
        "stop_cyclic",
        "switchover",
        "wait_for_timeout_alarm",
        "remove_callback",
        "stop_listener",
    ]
    switchover.assert_called_once_with(target=PLC.B, wait_for_ack=True)
    listener.add_rta_error_callback.assert_called_once_with(registered_callbacks[0])
    cyclic.stop.assert_called_once_with(send_stop_frames=False)
    rpc_a.close.assert_called_once_with(send_release=False)
    assert system.plcs[PLC.A].rpc is None
    assert system.plcs[PLC.A].alarm_listener is None
