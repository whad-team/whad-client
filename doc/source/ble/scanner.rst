Device scanning
===============

Bluetooth Low Energy scanning is provided by a dedicated connector, :class:`~whad.ble.connector.Scanner`,
that drives a BLE-enable WHAD device to detect any available BLE device. This connector relies
on an internal database implemented in :class:`~whad.ble.scanning.AdvertisingDevicesDB` that keeps
track of every detected device.

Discovering devices with this connector is pretty simple:

.. code-block:: python

    from whad.device import Device
    from whad.ble import Scanner

    # Access hardware interface hci0
    dev = Device.create("hci0")

    # Scan for devices for 30 seconds
    with Scanner(dev) as scanner:
        for device in scanner.discover_devices(timeout=30.0):
            print(device)

.. note::

    It is recommended to use the :class:`~whad.ble.Scanner` connector within a
    `with` statement to proper device initialization and cleanup.

Bluetooth Low Energy Scanner connector
--------------------------------------

.. autoclass:: whad.ble.connector.Scanner
    :members:
    :exclude-members: on_ctl_pdu, on_data_pdu, on_new_connection


BLE device tracking database
----------------------------

Devices are tracked by the BLE scanner connector by a dedicated database, each
device is then wrapped into a :class:`~whad.ble.scanning.AdvertisingDevice` instance
that holds all the interesting information.

.. autoclass:: whad.ble.scanning.AdvertisingDevice
    :members:

.. autoclass:: whad.ble.scanning.AdvertisingDevicesDB
    :members:
