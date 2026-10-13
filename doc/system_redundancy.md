# System Redundancy (S2)

The `SystemRedundancy` class coordinates two redundant IO-Controllers (`PLC.A` and `PLC.B`) connected to a single S2-capable PROFINET IO-Device via dual Application Relationships (ARs).

## What It Abstracts

- **Dual-AR Lifecycle Management**: Manages two independent IP endpoints, RPC sessions (`RPCCon`), cyclic RT controllers (`CyclicController`), and alarm listeners behind a unified controller pair.
- **Redundancy Role State Machine**:
  - Always connects new ARs with the **Backup** role (`DataStatus` bit 0 = 0).
  - Automates the multi-phase S2 parameterization sequence: backup parameterization (`prm_end` and `ApplicationReady`), role promotion to Primary (`switchover`), and primary reparameterization (`PrmBegin` &rarr; startup records / `WriteMultiple` &rarr; `PrmEnd` &rarr; `ApplicationReady`).
  - Implements non-preemptive role arbitration: `PLC.A` is the default preferred Primary when both are online. If `PLC.B` connects first while `PLC.A` is offline, `PLC.B` becomes Primary and `PLC.A` joins as Backup when brought online without triggering an unwanted switchover.
- **Synchronized Process Image**:
  - `update_io()` and `update_io_status()` update cyclic output frames and provider status across both controllers simultaneously, ensuring bumpless failover.
  - Automatically filters incoming cyclic data so the application callback only receives inputs from the active Primary.
- **Controlled Switchover & Role Acknowledgment**:
  - `switchover(target=...)` toggles roles between controllers and optionally waits for the IO-Device to acknowledge the new role in its cyclic APDU status (`slave_apdu_status`).
- **Failure Simulation & Seamless Recovery**:
  - `set_online(plc, False, wait_for_slave_timeout=True)` simulates silent controller drops without protocol teardown, allowing the device to trigger failover via watchdog timeout.
  - Reconnecting a controller automatically cleans up stale state and rejoins the AR as Backup.
- **Unified Alarm Handling**:
  - Aggregates alarms from both AR listeners into a single `on_alarm()` callback.

## Startup sequence

1) Only One PLC Online

``` mermaid
sequenceDiagram
    autonumber
    participant App as Application
    participant PLCA as PLC.x (Controller, online)
    participant Device as PROFINET Device (IO Device)

    %% --- Phase 1: PLC.A connects as Backup ---
    App->>PLCA: connect(PLC.A)
    PLCA->>Device: Connect.req (ARBlock, IOCRBlock, AlarmCRBlock)
    Device-->>PLCA: Connect.res (OK, frame IDs assigned)
    App->>PLCA: start(PLC.A)
    Note over PLCA,Device: Cyclic frames exchange starts (DataStatus: Backup)

    App->>PLCA: parameterize(PLC.A)
    Note over PLCA: Device not yet parameterized<br/>Step 1: Initial config as Backup
    PLCA->>Device: Write.req (Startup Parameters / WriteMultiple)
    Device-->>PLCA: Write.res (OK)
    PLCA->>Device: prm_end.req
    Device-->>PLCA: prm_end.rsp (OK)
    Device->>PLCA: ApplicationReady.req
    PLCA-->>Device: ApplicationReady.rsp (OK)

    %% --- Phase 2: PLC.A becomes Primary ---
    Note over PLCA: Step 2: Promote to Primary
    Note over PLCA,Device: Cyclic DataStatus becomes Primary
    Note over PLCA,Device: Wait until Device acknowledges Primary in IoData

    Note over PLCA: Step 3: Reparameterize as Primary
    PLCA->>Device: PrmBegin.req
    Device-->>PLCA: PrmBegin.res (OK)
    PLCA->>Device: prm_end.req
    Device-->>PLCA: prm_end.res (OK)
    Device->>PLCA: ApplicationReady.req
    PLCA-->>Device: ApplicationReady.res (OK)

    Note over PLCA,Device: PLC.x is Primary & fully parameterized
```

2) PLC.B Connects First, then PLC.A Connects (Both Online)

``` mermaid
sequenceDiagram
    autonumber
    participant App as Application
    participant PLCB as PLC.B
    participant PLCA as PLC.A
    participant Device as PROFINET Device (IO Device)

    %% --- Phase 1: PLC.B connects first ---
    Note over PLCB,Device: Phase 1: PLC.B connects first (both online)
    App->>PLCB: connect(PLC.B)
    Note over PLCB: CyclicController created (primary=False / Backup)
    PLCB->>Device: Connect.req (ARBlock, IOCRBlock, AlarmCRBlock)
    Device-->>PLCB: Connect.res (OK)
    App->>PLCB: start(PLC.B)
    Note over PLCB,Device: Cyclic frames exchange (DataStatus: Backup)

    App->>PLCB: parameterize(PLC.B)
    Note over PLCB: Initial config as Backup<br/>(Waits for preferred PLC.A to become Primary)
    PLCB->>Device: Write.req (Startup Parameters)
    Device-->>PLCB: Write.res (OK)
    PLCB->>Device: prm_end.req
    Device-->>PLCB: prm_end.res (OK)
    Device->>PLCB: ApplicationReady.req
    PLCB-->>Device: ApplicationReady.res (OK)

    %% --- Phase 2: PLC.A connects and becomes Primary ---
    Note over PLCA,Device: Phase 2: Preferred PLC.A connects
    App->>PLCA: connect(PLC.A)
    Note over PLCA: CyclicController created (primary=False / Backup)
    PLCA->>Device: Connect.req (ARBlock, IOCRBlock, AlarmCRBlock)
    Device-->>PLCA: Connect.res (OK)
    App->>PLCA: start(PLC.A)
    Note over PLCA,Device: Cyclic frames exchange (DataStatus: Backup)

    App->>PLCA: parameterize(PLC.A)
    Note over PLCA: Step 1: Backup config
    PLCA->>Device: prm_end.req
    Device-->>PLCA: prm_end.res (OK)
    Device->>PLCA: ApplicationReady.req
    PLCA-->>Device: ApplicationReady.res (OK)

    Note over PLCA: Step 2: Promote PLC.A to Primary
    Note over PLCA,Device: Cyclic DataStatus becomes Primary
    Note over PLCA,Device: Wait until Device acknowledges Primary in IoData

    Note over PLCA: Step 3: Reparameterize PLC.A as Primary
    PLCA->>Device: PrmBegin.req
    Device-->>PLCA: PrmBegin.res (OK)
    PLCA->>Device: prm_end.req
    Device-->>PLCA: prm_end.res (OK)
    Device->>PLCA: ApplicationReady.req
    PLCA-->>Device: ApplicationReady.res (OK)

    Note over PLCB,PLCA: System Redundant State:<br/>PLC.A = Primary (controlling outputs)<br/>PLC.B = Backup (synchronized standby)
```

3) PLC.B Connects First (PLC.A Offline), then PLC.A Comes Online Later

``` mermaid
sequenceDiagram
    autonumber
    participant App as Application
    participant PLCB as PLC.B
    participant PLCA as PLC.A
    participant Device as PROFINET Device (IO Device)

    %% --- Phase 1: Only PLC.B online ---
    Note over PLCB,Device: Phase 1: Only PLC.B online (PLC.A offline)
    App->>PLCB: connect(PLC.B) & start(PLC.B)
    App->>PLCB: parameterize(PLC.B)
    Note over PLCB: Backup config -> Switchover -> Primary Reparameterize
    PLCB->>Device: Write.req (Startup Parameters)
    PLCB->>Device: prm_end.req
    Device->>PLCB: ApplicationReady.req
    Note over PLCB,Device: Switchover to Primary & wait for Primary APDU ack
    PLCB->>Device: PrmBegin.req
    PLCB->>Device: prm_end.req
    Device->>PLCB: ApplicationReady.req
    Note over PLCB: PLC.B is Primary (_device_parameterized = True)

    %% --- Phase 2: PLC.A comes online later ---
    Note over PLCA,Device: Phase 2: PLC.A comes online later
    App->>PLCA: set_online(PLC.A, True)
    App->>PLCA: connect(PLC.A) and start(PLC.A)
    Note over PLCA,Device: Cyclic frames exchange (DataStatus: Backup)
    App->>PLCA: parameterize(PLC.A)
    Note over PLCA: Device already parameterized by PLC.B<br/>No switchover. PLC.A attaches as Backup
    PLCA->>Device: prm_end.req
    Device-->>PLCA: prm_end.res (OK)
    Device->>PLCA: ApplicationReady.req
    PLCA-->>Device: ApplicationReady.res (OK)

    Note over PLCB,PLCA: System Redundant State:<br/>PLC.B = Primary (controlling outputs)<br/>PLC.A = Backup (synchronized standby)
```