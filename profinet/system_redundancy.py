"""
PROFINET System Redundancy (S2) Helper.

Provides SystemRedundancy class for establishing paired System Redundancy ARs
(1st AR and 2nd AR) to a PROFINET device, constructing both RPCCon and
CyclicController instances in a single unified interface.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from . import dcp
from .alarm_listener import AlarmEndpoint, AlarmListener
from .alarms import AlarmNotification
from .cyclic import DEFAULT_MAX_CONSECUTIVE_TIMEOUTS, CyclicController, CyclicState
from .rpc import DEFAULT_TIMEOUT, ConnectResult, IOCRSetup, RPCCon, SRInfoConfig
from .rt import IOXS_GOOD, build_iocr_configs
from .util import get_mac, s2mac

logger = logging.getLogger(__name__)


class PLC(Enum):
    A = "A"
    B = "B"


@dataclass
class PLCConnection:
    """State and resources owned by one PLC's single System Redundancy AR."""

    name: PLC
    alarm_ref: int
    local_ip: str
    interface: str
    src_mac: bytes
    rpc: Optional[RPCCon]
    sr_info: SRInfoConfig
    online: bool = True
    initial_prm_end_done: bool = False
    initial_application_ready: bool = False
    startup_parameters: List[tuple[int, int, int, int, bytes]] = field(default_factory=list)
    result: Optional[ConnectResult] = None
    cyclic: Optional[CyclicController] = None
    alarm_listener: Optional[AlarmListener] = None


class SystemRedundancy:
    """Manage redundant PLC A/B connections, each with one System Redundancy AR.

    PLCs are selected with ``PLC.A`` and ``PLC.B`` and available as
    ``plcs[PLC.A]`` and ``plcs[PLC.B]``. Both are online by
    default. Configure ``online_plcs`` at startup or call :meth:`set_online` at
    runtime to take one offline. If both are online, PLC A is the preferred
    primary; if only one is online, that PLC becomes primary.
    """

    def __init__(
        self,
        info: dcp.DCPDeviceDescription,
        interface: str,
        primary_ip: str,
        secondary_ip: str,
        src_mac: bytes,
        iocr_setup: IOCRSetup,
        dst_mac: Optional[bytes] = None,
        timeout: float = DEFAULT_TIMEOUT,
        with_alarm_cr: bool = True,
        redundancy_data_hold_factor: int = 0x035D,
        max_consecutive_timeouts: int = DEFAULT_MAX_CONSECUTIVE_TIMEOUTS,
        online_plcs: Optional[Set[PLC]] = None,
        secondary_interface: Optional[str] = None,
        secondary_src_mac: Optional[bytes] = None,
        primary_plc: PLC = PLC.A,
    ) -> None:
        """Initialize System Redundancy helper without auto-connecting.

        Args:
            info: Device description from DCP discovery
            interface: Network interface name (e.g. "eth0")
            primary_ip: Primary IP address of the controller
            secondary_ip: Secondary IP address of the controller
            src_mac: Controller MAC address (6 bytes)
            iocr_setup: IOCRSetup configuration for cyclic IO
            dst_mac: Target device MAC address (auto-extracted from info if None)
            timeout: RPC socket timeout in seconds
            with_alarm_cr: Default AlarmCR setting for AR connects (default: True)
            redundancy_data_hold_factor: Hold factor if auto-generating sr_info pair
            max_consecutive_timeouts: Watchdog timeouts before FAULT state
            online_plcs: PLCs initially online; defaults to both ``PLC.A`` and ``PLC.B``.
            secondary_interface: Interface used by AR2. Defaults to the AR1
                interface, allowing two local IP addresses on one interface.
            secondary_src_mac: MAC used by AR2. If omitted with a distinct
                secondary interface, that interface's MAC is detected.
            primary_plc: Preferred true primary when both PLCs are online. If
                it is offline, the remaining online PLC takes over.
        """
        if dst_mac is None:
            raw_mac = info.mac
            if isinstance(raw_mac, bytes):
                dst_mac = raw_mac
            elif isinstance(raw_mac, str):
                dst_mac = s2mac(raw_mac)
            else:
                dst_mac = bytes(raw_mac)

        if primary_ip is None or secondary_ip is None:
            raise ValueError("Both primary_ip and secondary_ip must be provided.")

        device_network = ipaddress.IPv4Network((info.ip, info.netmask), strict=False)
        for plc_name, plc_ip in ((PLC.A, primary_ip), (PLC.B, secondary_ip)):
            if ipaddress.IPv4Address(plc_ip) not in device_network:
                raise ValueError(
                    f"PLC {plc_name.value} IP {plc_ip} is not in device subnet "
                    f"{device_network} (device {info.ip}, netmask {info.netmask})"
                )

        sr_info_by_ar = dict(
            enumerate(
                SRInfoConfig.create_pair(
                    redundancy_data_hold_factor=redundancy_data_hold_factor,
                ),
                start=1,
            )
        )

        self.info = info
        self.interface = interface
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.iocr_setup = iocr_setup
        self.timeout = timeout
        self.with_alarm_cr = with_alarm_cr
        self.max_consecutive_timeouts = max_consecutive_timeouts
        primary_plc = self._normalize_plc(primary_plc)
        online = set(online_plcs) if online_plcs is not None else {PLC.A, PLC.B}
        if any(not isinstance(name, PLC) for name in online):
            raise TypeError("online_plcs must contain PLC.A and/or PLC.B")
        self.primary_plc = primary_plc
        self._device_parameterized = False
        self._output_data: Dict[Tuple[int, int], bytes] = {}
        self._output_status: Dict[Tuple[int, int], int] = {}

        second_interface = secondary_interface or interface
        second_src_mac = secondary_src_mac
        if second_src_mac is None:
            second_src_mac = get_mac(second_interface) if secondary_interface else src_mac

        self.plcs: Dict[PLC, PLCConnection] = {}
        for name, local_ip, ar_interface, ar_src_mac, alarm_ref in (
            (PLC.A, primary_ip, interface, src_mac, 1),
            (PLC.B, secondary_ip, second_interface, second_src_mac, 2),
        ):
            is_online = name in online
            rpc = (
                RPCCon(info, timeout=timeout, ip_address=local_ip, alarm_ref=alarm_ref)
                if is_online
                else None
            )
            self.plcs[name] = PLCConnection(
                name=name,
                alarm_ref=alarm_ref,
                local_ip=local_ip,
                interface=ar_interface,
                src_mac=ar_src_mac,
                rpc=rpc,
                sr_info=sr_info_by_ar[alarm_ref],
                online=is_online,
            )
        self._alarm_callbacks: List[Callable[[AlarmNotification], None]] = []

        # Callbacks registered on SystemRedundancy to detect APDU changes of the IO device
        self._on_input_data: Optional[Callable[[int, int, bytes], None]] = None
        self._on_data_change: Optional[Callable[..., None]] = None
        self._on_backup_data_change: Optional[Callable[..., None]] = None
        self._on_input_status: Optional[Callable[[int, int, int], None]] = None
        self._on_slave_apdu_status: Optional[Callable[..., None]] = None
        self._on_timeout: Optional[Callable[[], None]] = None
        self._on_error: Optional[Callable[[str], None]] = None
        self._on_state_change: Optional[Callable[[CyclicState, CyclicState], None]] = None

    @staticmethod
    def _normalize_plc(plc: PLC) -> PLC:
        if not isinstance(plc, PLC):
            raise TypeError("plc must be PLC.A or PLC.B")
        return plc

    def _connections(
        self,
        plc: Optional[PLC] = None,
        *,
        include_offline: bool = False,
    ) -> List[PLCConnection]:
        if plc is None:
            connections = list(self.plcs.values())
        else:
            connections = [self.plcs[self._normalize_plc(plc)]]
        if include_offline:
            return connections
        return [connection for connection in connections if connection.online]

    def _active_primary(self) -> Optional[PLCConnection]:
        preferred = self.plcs[self.primary_plc]
        if preferred.online:
            return preferred
        return next((plc for plc in self.plcs.values() if plc.online), None)

    def _create_rpc(self, plc: PLCConnection) -> RPCCon:
        rpc = RPCCon(
            self.info,
            timeout=self.timeout,
            ip_address=plc.local_ip,
            alarm_ref=plc.alarm_ref,
        )
        for parameter in plc.startup_parameters:
            rpc.add_startup_parameter(*parameter)
        return rpc

    def _start_alarm_listener(self, connection: PLCConnection) -> None:
        rpc = connection.rpc
        if rpc is None or rpc._alarm_cr_enabled is not True:
            return

        if connection.alarm_listener:
            connection.alarm_listener.stop()

        endpoint = AlarmEndpoint(
            interface=connection.interface,
            controller_ref=rpc._alarm_ref,
            device_ref=rpc._device_alarm_ref,
            device_mac=self.dst_mac,
            transport=0,
        )
        listener = AlarmListener(endpoint, connection.src_mac)
        for callback in self._alarm_callbacks:
            listener.add_callback(callback)
        listener.start()

        connection.alarm_listener = listener

    def stop_alarm_listener(self, plc: Optional[PLC] = None) -> None:
        """Stop alarm handling for one PLC or all PLCs."""
        for connection in self._connections(plc, include_offline=True):
            if connection.alarm_listener:
                connection.alarm_listener.stop()
                connection.alarm_listener = None

    # --- Connection methods ---

    def _discard_previous_ar(self, connection: PLCConnection) -> None:
        """Stop leftovers of a dropped AR so the new one starts as a fresh backup."""
        if connection.cyclic is not None:
            connection.cyclic.stop(send_stop_frames=False)
            connection.cyclic = None
        self.stop_alarm_listener(connection.name)
        connection.result = None
        connection.initial_prm_end_done = False
        connection.initial_application_ready = False
        if not any(
            other.cyclic is not None and other.cyclic.is_running
            for other in self.plcs.values()
            if other is not connection
        ):
            self._device_parameterized = False

    def connect(
        self,
        plc: Optional[PLC] = None,
        with_alarm_cr: Optional[bool] = None,
        iocr_setup: Optional[IOCRSetup] = None,
    ) -> Optional[ConnectResult]:
        """Establish the selected AR(s) and create their cyclic controllers.

        Args:
            with_alarm_cr: Optional override for with_alarm_cr setting
            iocr_setup: Optional override for iocr_setup

        Returns:
            The selected AR's result, or the last result when connecting both.
        """

        w_alarm = self.with_alarm_cr if with_alarm_cr is None else with_alarm_cr
        setup = iocr_setup or self.iocr_setup
        results = []
        for connection in self._connections(plc):
            self._discard_previous_ar(connection)
            if connection.rpc is None:
                connection.rpc = self._create_rpc(connection)
            result = connection.rpc.connect(
                src_mac=connection.src_mac,
                with_alarm_cr=w_alarm,
                iocr_setup=setup,
                sr_info=connection.sr_info,
            )
            if not result or not result.has_cyclic:
                raise RuntimeError(f"PLC {connection.name.value} failed to establish cyclic IO")

            input_iocr, output_iocr = build_iocr_configs(
                slots=setup.slots,
                input_frame_id=result.input_frame_id,
                output_frame_id=result.output_frame_id,
                send_clock_factor=setup.send_clock_factor,
                reduction_ratio=setup.reduction_ratio,
                watchdog_factor=setup.watchdog_factor,
            )
            connection.cyclic = CyclicController(
                interface=connection.interface,
                src_mac=connection.src_mac,
                dst_mac=self.dst_mac,
                input_iocr=input_iocr,
                output_iocr=output_iocr,
                max_consecutive_timeouts=self.max_consecutive_timeouts,
                primary=False,
            )
            for (slot, subslot), data in self._output_data.items():
                connection.cyclic.set_output_data(slot, subslot, data)
            for (slot, subslot), status in self._output_status.items():
                connection.cyclic.set_output_status(slot, subslot, status)
            connection.initial_prm_end_done = False
            connection.initial_application_ready = False
            connection.result = result
            self._apply_callbacks(connection.cyclic)
            self._start_alarm_listener(connection)
            results.append(result)

        return results[-1] if results else None

    # --- Cyclic execution methods ---
    def start(self, plc: Optional[PLC] = None) -> None:
        """Start cyclic data exchange.

        Args:
            plc: PLC.A or PLC.B; None starts all online controllers.
        """
        for connection in self._connections(plc):
            if connection.cyclic is None:
                raise RuntimeError(
                    f"No CyclicController for PLC {connection.name.value} is connected yet"
                )
            connection.cyclic.start()

    def stop(
        self,
        plc: Optional[PLC] = None,
        *,
        send_stop_frames: bool = True,
    ) -> None:
        """Stop cyclic data exchange for one PLC or all online PLCs.

        Args:
            plc: PLC.A or PLC.B; None stops all online PLCs.
            send_stop_frames: Send graceful STOP frames. False lets the device
                detect AR loss by timeout.
        """
        for connection in self._connections(plc):
            if connection.cyclic:
                connection.cyclic.stop(send_stop_frames=send_stop_frames)

    def close(self, close_sockets: bool = True) -> None:
        """Gracefully stop and close all online PLC connections."""

        self.stop()
        self.stop_alarm_listener()
        for connection in self.plcs.values():
            try:
                if connection.rpc is not None:
                    if close_sockets:
                        connection.rpc.close(send_release=connection.online)
                        connection.rpc = None
                    elif connection.online:
                        connection.rpc.disconnect()
            except Exception as e:
                logger.debug(f"Error closing PLC {connection.name.value}: {e}")

    def set_online(
        self,
        plc: PLC,
        online: bool,
        wait_for_slave_timeout: bool = False,
    ) -> None:
        """Bring a PLC online or take it offline without a protocol shutdown.

        Offline PLCs stop transmitting immediately; the slave detects the lost
        AR through its timeout. Bringing one online recreates its local RPC
        socket; call connect/start/parameterize to establish the AR again.

        Args:
            plc: PLC.A or PLC.B to change.
            online: True to recreate its RPC socket; False to take it offline.
            wait_for_slave_timeout: Keep its alarm listener running until the
                slave reports an RTA ERROR after the AR timeout.
        """
        connection = self.plcs[self._normalize_plc(plc)]
        if connection.online == online:
            return

        if online:
            connection.rpc = self._create_rpc(connection)
            connection.online = True
            connection.initial_prm_end_done = False
            connection.initial_application_ready = False
            return

        listener = connection.alarm_listener
        timeout_event = threading.Event() if wait_for_slave_timeout else None
        on_rta_error = (lambda _status: timeout_event.set()) if timeout_event is not None else None
        if wait_for_slave_timeout:
            if listener is None or not listener.is_running:
                raise RuntimeError(
                    f"Cannot wait for PLC {connection.name.value} slave timeout: "
                    "its alarm listener is not running; connect with AlarmCR enabled first"
                )
            if on_rta_error is not None:
                listener.add_rta_error_callback(on_rta_error)

        connection.online = False
        try:
            if connection.cyclic is not None:
                connection.cyclic.stop(send_stop_frames=False)
                connection.cyclic = None
            survivor = self._active_primary()
            if survivor and survivor.cyclic and survivor.cyclic.is_running:
                self._promote_and_reconfigure(survivor)
            if timeout_event is not None:
                timeout_event.wait()
        finally:
            if listener is not None and on_rta_error is not None:
                listener.remove_rta_error_callback(on_rta_error)
            self.stop_alarm_listener(connection.name)
            if connection.rpc is not None:
                connection.rpc.close(send_release=False)
                connection.rpc = None
            connection.result = None
            connection.initial_prm_end_done = False
            connection.initial_application_ready = False
            if not any(plc.cyclic is not None for plc in self.plcs.values()):
                self._device_parameterized = False

    def _promote_and_reconfigure(
        self,
        plc: PLCConnection,
        timeout: float = 30.0,
        confirm_app_ready: bool = True,
        send_startup_parameters: bool = True,
        use_write_multiple: bool = True,
    ) -> None:
        if plc.cyclic is None or not plc.cyclic.is_running:
            return
        self._prepare_as_backup(
            plc,
            timeout=timeout,
            confirm_app_ready=confirm_app_ready,
            send_startup_parameters=send_startup_parameters,
            use_write_multiple=use_write_multiple,
        )
        if not plc.cyclic.is_primary:
            self.switchover(target=plc.name, wait_for_ack=True)
        if not self._device_parameterized:
            self.reparameterize(
                plc=plc.name,
                confirm_app_ready=confirm_app_ready,
                app_ready_timeout=timeout,
                wait_for_primary=True,
                primary_timeout=timeout,
                send_startup_parameters=send_startup_parameters,
                use_write_multiple=use_write_multiple,
            )
            self._device_parameterized = True

    def _prepare_as_backup(
        self,
        plc: PLCConnection,
        timeout: float,
        confirm_app_ready: bool,
        send_startup_parameters: bool,
        use_write_multiple: bool,
    ) -> None:
        if not plc.initial_prm_end_done:
            self.prm_end(
                plc=plc.name,
                send_startup_parameters=send_startup_parameters,
                use_write_multiple=use_write_multiple,
            )
            plc.initial_prm_end_done = True
        if confirm_app_ready and not plc.initial_application_ready:
            self.application_ready(timeout=timeout, plc=plc.name)
            plc.initial_application_ready = True

    # --- Parameterization and CONTROL methods ---

    def add_startup_parameter(
        self,
        api: int,
        slot: int,
        subslot: int,
        idx: int,
        data: bytes,
        plc: Optional[PLC] = None,
    ) -> SystemRedundancy:
        """Register a startup record write for one or both ARs.

        By default the same startup parameter is registered with both PLCs;
        pass ``plc=PLC.A`` or ``plc=PLC.B`` to target just one.
        """
        for connection in self._connections(plc, include_offline=True):
            parameter = (api, slot, subslot, idx, bytes(data))
            connection.startup_parameters.append(parameter)
            if connection.rpc is not None:
                connection.rpc.add_startup_parameter(*parameter)
        return self

    def update_io(self, slot: int, subslot: int, data: bytes) -> None:
        """Update process output data for every connected cyclic AR.

        Both the Primary and Backup AR retain the same output image so a
        subsequent switchover can continue with the current process data.
        """
        data = bytes(data)
        self._output_data[(slot, subslot)] = data
        for connection in self.plcs.values():
            if connection.cyclic is not None:
                connection.cyclic.set_output_data(slot, subslot, data)

    def update_io_status(self, slot: int, subslot: int, status: int = IOXS_GOOD) -> None:
        """Set the provider status (IOPS) for a submodule on every cyclic AR.

        The status persists across subsequent :meth:`update_io` calls.

        Args:
            slot: Slot number
            subslot: Subslot number
            status: IOXS_GOOD (0x80) or IOXS_BAD (0x00)
        """
        self._output_status[(slot, subslot)] = status
        for connection in self.plcs.values():
            if connection.cyclic is not None:
                connection.cyclic.set_output_status(slot, subslot, status)

    def _wait_for_slave_role(
        self,
        cyclic: CyclicController,
        plc: PLC,
        primary: bool,
        timeout: float,
        report: bool = False,
    ) -> None:
        expected_state = 1 if primary else 0
        status = cyclic.slave_apdu_status
        role = "Primary" if primary else "Backup"
        logger.debug(
            f"PLC {plc.value}: waiting for slave APDU {role} "
            f"(current={f'0x{status:02X}' if status is not None else 'none'})"
        )
        if status is not None and (status & 0x01) == expected_state:
            logger.debug(f"PLC {plc.value}: slave APDU already reports {role}")
            if report:
                print(f"    PLC {plc.value}: acknowledged {role}")
            return

        event = threading.Event()

        def on_status_change(*args: Any) -> None:
            new_status = args[-1] if args else None
            logger.debug(
                f"PLC {plc.value}: slave APDU update "
                f"{f'0x{status:02X}' if status is not None else 'none'} -> "
                f"{f'0x{new_status:02X}' if new_status is not None else 'none'}"
            )
            if new_status is not None and (new_status & 0x01) == expected_state:
                logger.debug(f"PLC {plc.value}: slave acknowledged {role}")
                if report:
                    print(f"    PLC {plc.value}: acknowledged {role}")
                event.set()

        cyclic.on_slave_apdu_status(on_status_change)

        status = cyclic.slave_apdu_status
        if status is not None and (status & 0x01) == expected_state:
            event.set()

        if not event.wait(timeout=timeout):
            raise RuntimeError(
                f"Timeout ({timeout}s) waiting for slave PLC {plc.value} APDU status {role}"
            )

    def wait_for_slave_primary(
        self,
        plc: Optional[PLC] = None,
        timeout: float = 30.0,
    ) -> None:
        """Wait until the slave (IO-Device) sends an APDU status with Primary bit set (0x01).

        Args:
            plc: PLC.A or PLC.B, or None for all online PLCs.
            timeout: Timeout in seconds to wait for Primary APDU status.

        Raises:
            RuntimeError: If CyclicController for target AR is not connected or timeout occurs.
        """
        targets = [
            (connection.name, connection.cyclic)
            for connection in self._connections(plc)
            if connection.cyclic is not None
        ]

        if not targets:
            raise RuntimeError(f"No connected CyclicController found for PLC {plc}")

        for plc_name, cyclic in targets:
            self._wait_for_slave_role(cyclic, plc_name, primary=True, timeout=timeout)

    def parameterize(
        self,
        plc: Optional[PLC] = None,
        confirm_app_ready: bool = True,
        app_ready_timeout: float = 30.0,
        send_startup_parameters: bool = True,
        use_write_multiple: bool = True,
    ) -> None:
        """Initialize the primary using backup and primary parameter phases.

        Startup records are first sent before PrmEnd while the selected AR is
        backup. Once the preferred online controller is running, it is switched
        to primary and reparameterized, sending the records again as primary.

        Args:
            plc: PLC.A or PLC.B, or None for all online PLCs.
            confirm_app_ready: Wait for and confirm ApplicationReady in each phase.
            app_ready_timeout: Timeout in seconds when waiting for ApplicationReady.
            send_startup_parameters: Write registered records before this
                PrmEnd. Defaults to true for initial primary setup; backup
                parameterize calls do not configure the device.
            use_write_multiple: Batch startup records into one write request.
        """
        selected_connections = [
            connection
            for connection in self._connections(plc)
            if connection.cyclic is not None and connection.cyclic.is_running
        ]
        selected = {connection.name for connection in selected_connections}
        for connection in selected_connections:
            self._prepare_as_backup(
                connection,
                timeout=app_ready_timeout,
                confirm_app_ready=confirm_app_ready,
                send_startup_parameters=send_startup_parameters,
                use_write_multiple=use_write_multiple,
            )

        if self._device_parameterized:
            return

        preferred = self.plcs[self.primary_plc]
        if preferred.online:
            if preferred.name not in selected:
                return
            target = preferred
        else:
            target = self._active_primary()
            if target is None or target.name not in selected:
                return

        if target.cyclic is None or not target.cyclic.is_running:
            return

        self._promote_and_reconfigure(
            target,
            timeout=app_ready_timeout,
            confirm_app_ready=confirm_app_ready,
            send_startup_parameters=send_startup_parameters,
            use_write_multiple=use_write_multiple,
        )

    def reparameterize(
        self,
        plc: Optional[PLC] = None,
        confirm_app_ready: bool = True,
        app_ready_timeout: float = 30.0,
        wait_for_primary: bool = True,
        primary_timeout: float = 30.0,
        send_startup_parameters: bool = True,
        use_write_multiple: bool = True,
    ) -> None:
        """Perform reparameterization sequence on the selected AR(s).

        1. If wait_for_primary is True (default), waits for the slave to report Primary APDU status (0x01).
        2. Starts reparameterization phase (prm_begin).
        3. Writes registered startup parameters when enabled.
        4. Ends parameter phase (PrmEnd).
        5. Optionally waits for ApplicationReady (confirm_app_ready, default True).

        Args:
            plc: PLC.A or PLC.B, or None for all online PLCs.
            confirm_app_ready: Wait for and confirm ApplicationReady after prm_end (default True).
            app_ready_timeout: Timeout in seconds when waiting for ApplicationReady.
            wait_for_primary: Wait for slave Primary APDU status before prm_begin (default True).
            primary_timeout: Timeout in seconds when waiting for Primary APDU status.
            send_startup_parameters: Write registered startup records before PrmEnd.
            use_write_multiple: Batch startup records into one write request.
        """
        if wait_for_primary:
            self.wait_for_slave_primary(plc=plc, timeout=primary_timeout)

        # Re-enter the parameter phase, rewrite startup records, and finish it.
        self.prm_begin(plc=plc)
        self.prm_end(
            plc=plc,
            send_startup_parameters=send_startup_parameters,
            use_write_multiple=use_write_multiple,
        )
        if confirm_app_ready:
            self.application_ready(timeout=app_ready_timeout, plc=plc)
        self._device_parameterized = True

    def prm_begin(self, plc: Optional[PLC] = None) -> Optional[bytes]:
        """Send PrmBegin control command.

        Args:
            plc: PLC.A or PLC.B, or None for all online PLCs.
        """
        results = [
            connection.rpc.prm_begin()
            for connection in self._connections(plc)
            if connection.rpc is not None
        ]
        return next((result for result in results if result is not None), None)

    def prm_end(
        self,
        plc: Optional[PLC] = None,
        send_startup_parameters: bool = False,
        use_write_multiple: bool = True,
    ) -> Optional[bytes]:
        """Send PrmEnd control command.

        Args:
            plc: PLC.A or PLC.B, or None for all online PLCs.
            send_startup_parameters: Write registered startup records before PrmEnd.
            use_write_multiple: Batch startup records into one write request.
        """
        results = [
            connection.rpc.prm_end(
                send_startup_parameters=send_startup_parameters,
                use_write_multiple=use_write_multiple,
            )
            for connection in self._connections(plc)
            if connection.rpc is not None
        ]
        return next((result for result in results if result is not None), None)

    def application_ready(
        self,
        timeout: float = 30.0,
        plc: Optional[PLC] = None,
    ) -> Optional[bytes]:
        """Wait for and confirm ApplicationReady from device.

        Args:
            timeout: Max seconds to wait per AR.
            plc: PLC.A or PLC.B, or None for all online PLCs.
        """
        results = [
            connection.rpc.application_ready(timeout=timeout)
            for connection in self._connections(plc)
            if connection.rpc is not None
        ]
        return next((result for result in results if result is not None), None)

    def switchover(
        self,
        plc: Optional[PLC] = None,
        target: Optional[PLC] = None,
        wait_for_ack: bool = False,
        ack_timeout: float = 30.0,
    ) -> None:
        """Switch primary/backup roles of the online PLC cyclic controllers.

        Args:
            plc: PLC to toggle. If omitted with no target, toggle both online PLCs.
            target: PLC.A or PLC.B to make primary and the other online PLC backup.
            wait_for_ack: Wait for the device to report the new APDU roles.
            ack_timeout: Maximum wait for each role acknowledgement.
        """
        connections = self._connections()
        before_roles = {
            connection.name: connection.cyclic.is_primary if connection.cyclic else None
            for connection in connections
        }

        if target is not None:
            target = self._normalize_plc(target)
            if not self.plcs[target].online:
                raise ValueError(f"Cannot make offline PLC {target.value} primary")
            for connection in connections:
                cyclic = connection.cyclic
                if cyclic is not None and cyclic.is_primary != (connection.name == target):
                    cyclic.switchover()
        elif plc is not None:
            connection = self.plcs[self._normalize_plc(plc)]
            if connection.online and connection.cyclic is not None:
                connection.cyclic.switchover()
        else:
            for connection in connections:
                if connection.cyclic is not None:
                    connection.cyclic.switchover()

        after_roles = {
            connection.name: connection.cyclic.is_primary if connection.cyclic else None
            for connection in connections
        }

        if wait_for_ack:
            for connection in self._connections(plc):
                cyclic = connection.cyclic
                if cyclic is None or before_roles[connection.name] == after_roles[connection.name]:
                    continue
                expected_primary = cyclic.is_primary
                if not cyclic.is_running:
                    logger.warning(
                        "PLC %s cyclic controller is not running; skipping role wait",
                        connection.name.value,
                    )
                    continue
                self._wait_for_slave_role(
                    cyclic,
                    connection.name,
                    primary=expected_primary,
                    timeout=ack_timeout,
                    report=True,
                )

    # --- Callbacks wiring ---

    def on_alarm(self, callback: Callable[[AlarmNotification], None]) -> None:
        """Register a callback for alarms received on either AR."""
        self._alarm_callbacks.append(callback)
        for connection in self.plcs.values():
            if connection.alarm_listener:
                connection.alarm_listener.add_callback(callback)

    def _apply_callbacks(self, cyclic: CyclicController) -> None:
        if self._on_input_data:
            callback = self._on_input_data

            def on_primary_input(slot: int, subslot: int, data: bytes) -> None:
                if cyclic.is_primary:
                    callback(slot, subslot, data)

            cyclic.on_input(on_primary_input)
        if self._on_data_change or self._on_backup_data_change:

            def on_role_data_change(*args: Any) -> None:
                if cyclic.is_primary:
                    if self._on_data_change:
                        self._on_data_change(*args)
                elif self._on_backup_data_change:
                    self._on_backup_data_change(*args)

            cyclic.on_data_change(on_role_data_change)
        if self._on_input_status:
            cyclic.on_input_status(self._on_input_status)
        if self._on_slave_apdu_status:
            cyclic.on_slave_apdu_status(self._on_slave_apdu_status)
        if self._on_timeout:
            cyclic.on_timeout(self._on_timeout)
        if self._on_error:
            cyclic.on_error(self._on_error)
        if self._on_state_change:
            cyclic.on_state_change(self._on_state_change)

    def on_input(self, callback: Callable[[int, int, bytes], None]) -> None:
        self._on_input_data = callback
        for connection in self.plcs.values():
            if connection.cyclic:
                self._apply_callbacks(connection.cyclic)

    def on_data_change(self, callback: Callable[..., None]) -> None:
        """Register a Primary-AR callback for input payload and status changes.

        The callback receives ``(slot, subslot, old_data, data, old_iops,
        iops, old_apdu_status, apdu_status)``.
        """
        self._on_data_change = callback
        for connection in self.plcs.values():
            if connection.cyclic:
                self._apply_callbacks(connection.cyclic)

    def on_backup_data_change(self, callback: Callable[..., None]) -> None:
        """Register a Backup-AR callback for input payload and status changes.

        The callback receives ``(slot, subslot, old_data, data, old_iops,
        iops, old_apdu_status, apdu_status)``.
        """
        self._on_backup_data_change = callback
        for connection in self.plcs.values():
            if connection.cyclic:
                self._apply_callbacks(connection.cyclic)

    def on_input_status(self, callback: Callable[[int, int, int], None]) -> None:
        self._on_input_status = callback
        for connection in self.plcs.values():
            if connection.cyclic:
                connection.cyclic.on_input_status(callback)

    def on_slave_apdu_status(self, callback: Callable[..., None]) -> None:
        self._on_slave_apdu_status = callback
        for connection in self.plcs.values():
            if connection.cyclic:
                connection.cyclic.on_slave_apdu_status(callback)

    def on_timeout(self, callback: Callable[[], None]) -> None:
        self._on_timeout = callback
        for connection in self.plcs.values():
            if connection.cyclic:
                connection.cyclic.on_timeout(callback)

    def on_error(self, callback: Callable[[str], None]) -> None:
        self._on_error = callback
        for connection in self.plcs.values():
            if connection.cyclic:
                connection.cyclic.on_error(callback)

    def on_state_change(self, callback: Callable[[CyclicState, CyclicState], None]) -> None:
        self._on_state_change = callback
        for connection in self.plcs.values():
            if connection.cyclic:
                connection.cyclic.on_state_change(callback)

    def __enter__(self) -> SystemRedundancy:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
