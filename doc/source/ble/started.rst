Getting started
===============

.. contents::
   :local:

WHAD provides a set of classes and features related to Bluetooth Low Energy allowing
to advertise, scan, connect, interact and even emulate BLE devices. This section
introduces these different classes with minimal examples to get you started.

Send advertisements with no connection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the :class:`~whad.ble.connector.advertiser.Advertiser` class to instantiate
a BLE advertiser and send advertisements on Bluetooth Low Energy's advertising
channels (*i.e. channels 37, 38, 39*).

.. code-block:: python

    from whad.device import Device
    from whad.ble import Advertiser, AdvDataFieldList, AdvFlagsField, AdvCompleteLocalName
    from whad.hub.ble import AdvType

    advert = Advertiser(
        # Use device 'hci0' (Bluetooth HCI adapter)
        Device.create("hci0"),

        # Set advertising data
        AdvDataFieldList(
            # Add a default flags AD record
            AdvFlagsField(),
            # Add a complete local name AD record
            AdvCompleteLocalName(b"AdvertiserDemo")
        ),

        # No scan response data
        None,

        # Use a non-connectable undirected advertisement type
        AdvType.ADV_NONCONN_IND,

        # Advertise on all channels
        channels=[37,38,39]
    )

    # Start advertising
    advert.start()

    # Wait for a keypress to stop
    input('Press a key to stop advertising device ...')
    advert.stop()
    advert.close()

This example advertises a device named `AdvertiserDemo` that is announced as non-connectable.
Nordic's *NRF Connect* application can be used to check the advertised device exposes the
specified advertisement record and is non-connectable, as shown below.


.. image:: /images/ble/advertiser_nrfconnect.png
   :alt: NRF Connect application showing a non-connectable device named "AdvertiserDemo"
   :width: 400px
   :align: center


The device's advertising data and scan response data can be updated at any moment by accessing
the instance's ``adv_data`` and ``scan_data`` properties:

.. code-block:: python

    advert.adv_data = AdvDataFieldList(AdvFlagsField(), AdvCompleteLocalName(b"ChangedName"))

Advertisement core parameters like the advertisement type used, channel map or even
advertising interval can be updated by using their associated properties but only when the
advertiser is stopped.

Enumerating available devices (scanning)
----------------------------------------

Use the :class:`~whad.ble.connector.scanner.Scanner` class to instantiate
a BLE device scanner and detect all the available devices.

.. code-block:: python

    from whad.device import Device
    from whad.ble import Scanner

    scanner = Scanner(Device.create("hci0"))
    scanner.start()
    for rssi, advertisement in scanner.discover_devices():
        advertisement.show()

:class:`~whad.ble.connector.scanner.Scanner` can also be used within a
`with` statement, as shown below:

.. code-block:: python

    from whad.device import Device
    from whad.ble import Scanner

    with Scanner(Device.create("hci0")) as scanner:
        for device in scanner.discover_devices():
            print(device)

Initiating a connection to a BLE device
---------------------------------------

Use the :class:`~whad.ble.connector.central.Central` class to create a
BLE central device and initiate a connection to a BLE peripheral device.

.. code-block:: python

    from whad.device import Device
    from whad.ble import Central

    # Create a central device
    central = Central(Device.create("hci0"))

    # Connect to our target device
    target = central.connect('0C:B8:15:C4:88:8E')

The `connect()` method returns a :class:`~whad.ble.profile.device.PeripheralDevice` object
that represents the remote device.

Enumerating services and characteristics
----------------------------------------

Once connected, it is possible to discover all the services and characteristics
and display them.

.. code-block:: python

    # Discover services and characteristics
    target.discover()

    # Display target profile
    print(target)

The :class:`~whad.ble.profile.device.PeripheralDevice` object returned by :py:meth:`~whad.ble.connector.Central.connect`
provides some methods to iterate over services and characteristics:

.. code-block:: python

    for service in target.services():
        print('-- Service %s' % service.uuid)
        for charac in service.characteristics():
            print(' + Characteristic %s' % charac.uuid)

Reading a characteristic's value
--------------------------------

To read a characteristic from a connected device, just get the corresponding characteristic object
and read its value:

.. code-block:: python

        # Search for the DeviceName characteristic (0x2A00)
        # in the Generic Access Service (0x1800)
        charac = device.char('2a00', '1800')
        if charac is not None:
            # If found, read its value.
            print('Value: %s' % charac.value)
