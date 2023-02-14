Central role
============

Bluetooth Low Energy central role is used to connect to a BLE peripheral and
interact with it. WHAD provides a specific connector, :class:`whad.ble.connector.Central`,
that implements this role.

It also provides a specific wrapper for connected devices in order to mask the
underlying GATT stack and allow easy access to device services and charactersitics,
:class:`whad.ble.profile.device.PeripheralDevice`.

Bluetooth Low Energy Central connector
--------------------------------------

.. autoclass:: whad.ble.connector.Central
    :members:

.. automodule:: whad.ble.profile.device
    :members: PeripheralDevice