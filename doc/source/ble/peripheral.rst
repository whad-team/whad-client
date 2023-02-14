Peripheral role
===============

WHAD provides a specific connector to create a BLE device, :class:`whad.ble.connector.Peripheral`.
This connector implements a GATT server and hosts a GATT profile, allowing remote
BLE devices to connect to it and query its services, characteristics, and descriptors.

The connector provides some callbacks such as :meth:`whad.ble.connector.Peripheral.on_connected` to
react on specific events.

Bluetooth Low Energy Peripheral connector
-----------------------------------------

.. automodule:: whad.ble.connector
    :members: Peripheral
