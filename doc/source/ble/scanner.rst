Device Scanning
===============

.. py:currentmodule:: whad.ble.connector.scanner

Bluetooth Low Energy scanning is provided by a dedicated connector, :class:`~.Scanner`,
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

    It is recommended to use the :class:`~.Scanner` connector within a
    `with` statement for proper device initialization and cleanup.

By default, :class:`~.Scanner.discover_devices` yields a :class:`~whad.ble.scanning.AdvertisingDevice`
object only once each time a new device is detected, to avoid a device to be reported multiple times.
This behavior can be changed by setting its optional parameter `updates` to `True`, forcing this method
to continuously yield updated :class:`~whad.ble.scanning.AdvertisingDevice` objects no matter if they
are new devices detected or previously reported. Deduplication and processing is then left to the caller.

The following code shows a scanner that implements this feature and will continuously report all detected
devices:

.. code-block:: python

    from whad.device import Device
    from whad.ble import Scanner

    # Access hardware interface hci0
    dev = Device.create("hci0")

    # Scan for devices for 30 seconds, asks for updated information
    with Scanner(dev) as scanner:
        for device in scanner.discover_devices(timeout=30.0, updates=True):
            print(device)


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
