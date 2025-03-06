Central role
============

Bluetooth Low Energy central role is used to connect to a BLE peripheral and
interact with it. WHAD provides a specific connector, :class:`whad.ble.connector.Central`,
that implements this role.

It is possible to register a callback function to be called whenever an
asynchronous event is received by this connector using its :py:meth:`whad.ble.connector.central.Central.add_event_handler` method. This callback function will be called every time
a central-related event is received.

A :py:class:`whad.ble.connector.central.CentralConnected` event is sent when the
current Central connector has successfully connected to a device and a 
:py:class:`whad.ble.connector.central.CentralDisconnected` event is sent when
the remote device has disconnected.

It also provides a specific wrapper for connected devices in order to mask the
underlying GATT stack and allow easy access to device services and charactersitics,
:class:`whad.ble.profile.device.PeripheralDevice`.

.. important::

    The mechanism used to handle asynchronous events like connection and disconnection
    is still a work in progress. It has been introduced in a recent update to better
    handle connection and disconnection events and is not yet intended to be used
    by anything other WHAD's internal code.

    We have a full rework of WHAD's internals planned, including BLE Central and Peripheral
    classes, that will definitely bring some changes to the way connectors work. We will do
    our best not to break the current implementation.

Bluetooth Low Energy Central connector
--------------------------------------

.. autoclass:: whad.ble.connector.Central
    :members:

.. automodule:: whad.ble.profile.device
    :members: PeripheralDevice

Bluetooth Low Energy Central events
-----------------------------------

.. autoclass:: whad.ble.connector.central.CentralConnected
    :members:

.. autoclass:: whad.ble.connector.central.CentralDisconnected
    :members: