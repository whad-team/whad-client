Implementing a WHAD compatible firmware for Bluetooth
=====================================================

Each BLE-enabled WHAD device SHALL supports all the mandatory messages
introduced in this guide in order to be compatible with any WHAD BLE tool.

The following state diagram show the various states the WHAD device can take,
and the commands causing this state to change from one to another. This would
give you a first idea of what a WHAD BLE state machine looks like.

.. mermaid::

    stateDiagram-v2
        direction TB
        IDLE --> OBSERVER: ScanModeCmd
        OBSERVER --> OBSERVER_RUN: StartCmd
        OBSERVER_RUN --> OBSERVER: StopCmd
        OBSERVER --> PERIPH: PeripheralModeCmd
        OBSERVER --> CENTRAL: CentralModeCmd

        IDLE --> CENTRAL: CentralModeCmd
        CENTRAL --> CENTRAL_RUN: StartCmd
        CENTRAL_RUN --> CENTRAL: StopCmd
        CENTRAL --> CENTRAL: ConnectToCmd
        CENTRAL --> PERIPH: PeripheralModeCmd
        CENTRAL --> OBSERVER: ScanModeCmd

        IDLE --> PERIPH: PeripheralModeCmd
        PERIPH --> PERIPH_RUN: StartCmd
        PERIPH_RUN --> PERIPH: StopCmd
        PERIPH --> PERIPH: SetAdvDataCmd
        PERIPH --> OBSERVER: ScanModeCmd
        PERIPH --> CENTRAL: CentralModeCmd

Each BLE compatible device SHALL support three different modes:

* An observer mode (also known as "scanner"): the device listens to advertisements and send them to the host
* A central mode: device initiates a connection to a peripheral and allows host to send and receive PDUs
* A peripheral mode: device accepts a connection from a central and allows host to send and receive PDUs


If a device cannot provide access to complete BLE packets and metadata (including *access address*,
current channel, RSSI, timestamp and CRC), it SHALL handle PDU sending and receive operations through
limited PDU messages such as `SendPDUCmd` and `PduReceived`. These messages only provide the payload
PDU without any other metadata such as CRC status, timestamp or *access address*. 

Bluetooth Observer role
-----------------------

Observer role is enabled through a `ScanModeCmd` message that switches its
internal state to observer. Scanning is started once a `StartCmd` message is
received, and stopped whenever a `StopCmd` is received. Scanner notifies the
host of every discovered BLE device when active.

.. mermaid::

    sequenceDiagram

        participant Host
        participant Device

        Host->>+Device: ScanModeCmd
        Note right of Device: internal state changed to Observer mode
        Device->>-Host: ScanResult(Success)

        Host->>Device: StartCmd
        activate Device
        Device->>Host: CmdResult(Success)

        Device-->>Host: PduReceived
        Device-->>Host: PduReceived

        Host->>+Device: StopCmd
        Device->>-Host: CmdResult(Success)

        deactivate Device




Bluetooth Central role
----------------------

Central mode is enabled through a specific `CentralModeCmd` that switches its
internal state to central. The target device BD address SHALL be provided before
starting in central mode, i.e. before sending the `StartCmd` message. Once started,
the device will forward any received PDU to the host through `PduReceived` messages
and the host itself can send messages by using `SendPduCmd` messages.

When host issues a `StopCmd`, the device disconnects from the remote peripheral
and returns to idle mode.

Central role sequence diagram
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. mermaid::

    sequenceDiagram
        participant Host
        participant Device
        Host->>+Device: CentralModeCmd
        Note right of Device: internal state changed to Central mode
        Device->>-Host: CmdResult(Success)

        Host->>+Device: ConnectToCmd
        Note right of Device: Target BD address is set
        Device->>-Host: CmdResult(Success)

        Host->>Device: StartCmd
        activate Device
        Note right of Device: Device starts connecting to target
        Device->>Host: CmdResult(Success)

        Note over Host, Device: Device connecting to target

        Device-->>Host: Connected

        opt Sending PDU
            Host-->>+Device: SendPDUCmd
            Note right of Device: Add PDU in transmit queue
            Device-->>-Host: CmdResult(Success)
        end

        opt Received PDU
            Device-->>Host: PduReceived
            activate Host
            Note left of Host: Processes incoming PDU
            deactivate Host
        end

        Host->>+Device: StopCmd
        Note right of Device: Device disconnects from target
        Device->>-Host: CmdResult(Success)

        Note over Host, Device: Connection is terminated

        Device-->>Host: Disconnected

        deactivate Device


If no target BD address has been set by the host when a `StartCmd` is received,
Device SHALL send a `CmdResult` message with its `result` property set to
`ResultCode.ERROR`. 

If a `StartCmd` is received by the Device while it has already been started, 
Device SHALL send a `CmdResult` message with its `result` property set to
`ResultCode.ERROR`. 

If a `ConnectToCmd` is received after the Device has started in Central mode,
Device SHALL responds with a `CmdResult` message with its `result` property
set to `ResultCode.ERROR`. Host must disconnect first and then change target BD
address.


Bluetooth Peripheral role
-------------------------

Peripheral mode is enabled through a specific `PeripheralModeCmd` message that
switches its internal state to peripheral. Host then sets the peripheral advertising
data and scan response, before starting the peripheral through a `StartCmd` message.

Once the peripheral has started, it sends advertisements on each advertising channel
based on the provided configuration and awaits for a connection from a Central device.

When a Central device has successfully connected to it, it sends a connection
notification and every received PDU to the Host. The Host can send PDUs to the
remote Central device by using a `SendPDUCmd` or `SendRawPDUCmd` depending on
the Device capabilities. 

When the Central device disconnects from the peripheral, a disconnection
notification is sent to the Host.

The Host can also decide to terminate an existing connection by sending a
`StopCmd` to the Device, which immediately terminates the connection and send
a disconnection notification when done.

Peripheral role sequence diagram
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. mermaid::

    sequenceDiagram
        participant Host
        participant Device

        Host->>+Device: PeripheralModeCmd
        Device->>-Host: CmdResult(Success)

        Host->>+Device: SetAdvDataCmd
        Note right of Device: Configure advertising and scan data
        Device->>-Host: CmdResult(Success)

        Host->>Device: StartCmd
        activate Device
        Note over Host, Device: Device starts advertising

        Device-->>Host: Connected(handle)
        activate Host
        Note left of Host: Processes incoming connection
        deactivate Host

        opt Sending PDU
            Host-->>+Device: SendPDUCmd
            Note right of Device: Add PDU in transmit queue
            Device-->>-Host: CmdResult(Success)
        end

        opt Received PDU
            Device-->>Host: PduReceived
            activate Host
            Note left of Host: Processes incoming PDU
            deactivate Host
        end

        Host->>+Device: StopCmd
        Note right of Device: Device terminates connection
        Device->>-Host: CmdResult(Success)

        Note over Host, Device: Connection is terminated

        Device-->>Host: Disconnected

        deactivate Device

If a `StartCmd` is received but advertising data have not been previously set,
the Device SHALL responds with a `CmdResult` message with a `result` set to
`ResultCode.ERROR`.


Device supporting Raw PDUs
--------------------------

If a device provides access to raw BLE packets including *access address*, CRC,
channel and RSSI, then it SHALL supports `SendRawPDUCmd` and sends `RawPduReceived`
notifications each time a packet is received. Raw packets will always be preferred
by WHAD even if a device supports both raw and non-raw packets. 

.. mermaid::

    sequenceDiagram
        participant Host
        participant Device

        activate Device

        opt Sending raw PDU
            Host-->>+Device: SendRawPDUCmd
            Note right of Device: Add PDU in transmit queue
            Device-->>-Host: CmdResult(Success)
        end

        opt Received raw PDU
            Device-->>Host: RawPduReceived
            activate Host
            Note left of Host: Processes incoming PDU
            deactivate Host
        end

        deactivate Device
