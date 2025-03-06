Peripheral role
===============

WHAD provides a specific connector to create a BLE device, :class:`whad.ble.connector.Peripheral`.
This connector implements a GATT server and hosts a GATT profile, allowing remote
BLE devices to connect to it and query its services, characteristics, and descriptors.

The Peripheral connector allows to register a single event listener of class 
:py:class:`whad.ble.connector.peripheral.PeripheralEventListener`
through its :py:meth:`Peripheral.attach_event_listener` method. This event listener must
be created with a callback function attached that will be called by the connector to
notify any connection or disconnection event (respectively a :py:class:`whad.ble.connector.peripheral.PeripheralEventConnected` and :py:class:`whad.ble.connector.peripheral.PeripheralEventDisconnected`
instance).

.. important::

    The mechanism used to handle asynchronous events like connection and disconnection
    is still a work in progress. It has been introduced in a recent update to better
    handle connection and disconnection events and is not yet intended to be used
    by anything other WHAD's internal code.

    We have a full rework of WHAD's internals planned, including BLE Central and Peripheral
    classes, that will definitely bring some changes to the way connectors work. We will do
    our best not to break the current implementation.

Bluetooth Low Energy Peripheral connector
-----------------------------------------

.. automodule:: whad.ble.connector
    :members: Peripheral

Bluetooth Low Energy Peripheral events
--------------------------------------

.. autoclass:: whad.ble.connector.peripheral.PeripheralEventConnected
    :members:

.. autoclass:: whad.ble.connector.peripheral.PeripheralEventDisconnected
    :members: