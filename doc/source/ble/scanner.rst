Device scanning
===============

Bluetooth Low Energy scanning is provided by a dedicated connector, :class:`whad.ble.connector.Scanner`,
that drives a BLE-enable WHAD device to detect any available BLE device. This connector relies
on an internal database implemented in :class:`whad.ble.scanning.AdvertisingDevicesDB` that keeps
track of every detected device.

Bluetooth Low Energy Scanner connector
--------------------------------------

.. autoclass:: whad.ble.connector.Scanner
    :members:
    :exclude-members: on_ctl_pdu, on_data_pdu, on_new_connection


BLE device tracking database
----------------------------

Devices are tracked by the BLE scanner connector by a dedicated database, each
device is then wrapped into a :class:`whad.ble.scanning.AdvertisingDevice` instance
that holds all the interesting information.

.. autoclass:: whad.ble.scanning.AdvertisingDevice
    :members:

.. autoclass:: whad.ble.scanning.AdvertisingDevicesDB
    :members:
