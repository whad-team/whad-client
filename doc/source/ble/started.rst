Getting started
===============

Scan available devices
~~~~~~~~~~~~~~~~~~~~~~

Use the :class:`whad.ble.connector.scanner.Scanner` class to instantiate
a BLE device scanner and detect all the available devices.

.. code-block:: python

    from whad.device import Device
    from whad.ble import Scanner

    scanner = Scanner(Device.create("hci0"))
    for device in scanner.discover_devices():
        print(device)

:class:`~whad.ble.connector.scanner.Scanner` can also be used within a
`with` statement, as shown below:

.. code-block:: python

    from whad.device import Device
    from whad.ble import Scanner

    with Scanner(Device.create("hci0")) as scanner:
        for device in scanner.discover_devices():
            print(device)

Initiate a connection to a BLE device
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the :class:`~whad.ble.connector.central.Central` class to create a
BLE central device and initiate a connection to a BLE peripheral device.

.. code-block:: python

    from whad import UartDevice
    from whad.ble import Central

    # Create a central device
    central = Central(UartDevice('/dev/ttyUSB0'))

    # Connect to our target device
    target = central.connect('0C:B8:15:C4:88:8E')

The `connect()` method returns a :class:`whad.ble.profile.device.PeripheralDevice` object
that represents the remote device.

Enumerate services and characteristics
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once connected, it is possible to discover all the services and characteristics
and display them.

.. code-block:: python

    # Discover services and characteristics
    target.discover()

    # Display target profile
    print(target)

The :class:`whad.ble.profile.device.PeripheralDevice` also provides some methods
to iterate over services and characteristics:

.. code-block:: python

    for service in target.services():
        print('-- Service %s' % service.uuid)
        for charac in service.characteristics():
            print(' + Characteristic %s' % charac.uuid)

Read a characteristic
~~~~~~~~~~~~~~~~~~~~~

To read a characteristic from an device, just get the corresponding characteristic object
and read its value:

.. code-block:: python

    charac = device.get_characteristic(UUID('1800'), UUID('2A00'))
    if charac is not None:
        print('Value: %s' % charac.value)

Write to characteristic
~~~~~~~~~~~~~~~~~~~~~~~

To write a value into a characteristic, this is as simple as reading one:

.. code-block:: python

    charac = device.get_characteristic(UUID('1800'), UUID('2A00'))
    if charac is not None:
        charac.value = b'Something'

Subscribe for notification/indication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sometimes it is needed to subscribe to notifications or indications for a given
characteristic. This is done through the `subscribe()` method of :class:`whad.ble.profile.device.PeripheralDevice`, as shown below:

.. code-block:: python

    def on_charac_updated(characteristic, value, indication=False):
        if indication:
            print('[indication] characteristic updated with value: %s' % value)
        else:
            print('[notification] characteristic updated with value: %s' % value)

    charac = device.get_characteristic(UUID('1800'), UUID('2A00'))
    if charac is not None:
        charac.subscribe(
            notification=True,
            callback=on_charac_updated
        )

Close connection
~~~~~~~~~~~~~~~~

To close an existing connection, simply call the `disconnect()` method of the :class:`whad.ble.profile.device.PeripheralDevice` class:

.. code-block:: python

    target.disconnect()


Create a peripheral device
~~~~~~~~~~~~~~~~~~~~~~~~~~

Creating a BLE peripheral device requires to define a custom profile that determines
the device services and characteristics:

.. code-block:: python

    from whad import UartDevice
    from whad.ble import Peripheral
    from whad.ble.profile import GattProfile
    from whad.ble.profile.advdata import AdvCompleteLocalName, AdvDataFieldList, AdvFlagsField

    class MyPeripheral(GenericProfile):

        device = PrimaryService(
            uuid=UUID(0x1800),

            device_name = Characteristic(
                uuid=UUID(0x2A00),
                permissions = ['read', 'write'],
                notify=True,
                value=b'TestDevice'
            ),

            null_char = Characteristic(
                uuid=UUID(0x2A01),
                permissions = ['read', 'write'],
                notify=True,
                value=b''
            ),
        )

Once this profile defined, instantiate a :class:`whad.ble.connector.Peripheral` object
using this profile:

.. code-block:: python

    # Instantiate our peripheral
    my_profile = MyPeripheral()

    # Create a periphal device based on this profile
    periph = Peripheral(UartDevice('/dev/ttyUSB0', 115200), profile=my_profile)

    # Enable peripheral mode with advertisement data:
    # * default flags (general discovery mode, connectable, BR/EDR not supported)
    # * Complete local name
    periph.enable_peripheral_mode(adv_data=AdvDataFieldList(
        AdvCompleteLocalName(b'TestMe!'),
        AdvFlagsField()
    ))

    # Start advertising
    periph.start()

It is also possible to trigger specific actions when a characteristic is read or written,
through the dedicated callbacks provided by :class:`whad.ble.profile.GenericProfile`.

Advanced features
-----------------

Sending and receiving PDU
~~~~~~~~~~~~~~~~~~~~~~~~~

It is sometimes useful to send a PDU to a device as well as processing any
incoming PDU without having to use a protocol stack. The BLE :py:class:`whad.ble.connector.Peripheral`
and :py:class:`whad.ble.connector.Central` connector provides a nifty way to do it:

.. code:: python

    from whad.ble import Central
    from whad.device import WhadDevice
    from scapy.layers.bluetooth4LE import *

    # Connect to target
    print('Connecting to remote device ...')
    central = Central(WhadDevice.create('uart0'))
    device = central.connect('00:11:22:33:44:55', random=False)

    # Make sure connection has succeeded
    if device is not None:

        # Enable synchronous mode: we must process any incoming BLE packet.
        central.enable_synchronous(True)

        # Send a LL_VERSION_PDU
        central.send_pdu(BTLE_DATA()/BTLE_CTRL()/LL_VERSION_IND(
            version = 0x08,
            company = 0x0101,
            subversion = 0x0001
        ))

        # Wait for a packet
        while central.is_connected():
            pdu = central.wait_packet()
            if pdu.haslayer(LL_VERSION_IND):
                pdu[LL_VERSION_IND].show()
                break

        # Disconnect
        device.disconnect()

The above example connects to a target device, sends an `LL_VERSION_IND`
PDU and waits for an `LL_VERSION_IND` PDU from the remote device.

Normally, when a :class:`whad.device.connector.WhadDeviceConnector`
(or any of its inherited classes) is used it may rely on a protocol stack to process
outgoing and ingoing PDUs. By doing so, there is no way to get access to the received
PDUs and avoid them to be forwarded to the connector's protocol stack.

However, all connectors expose a method called :meth:`whad.device.connector.WhadDeviceConnector.enable_synchronous`
that can enable or disable this automatic processing of PDUs. By default,
PDUs are passed to the underlying protocol stack but we can force the connector
to keep them in a queue and to wait for us to retrieve them:

.. code:: python

    # Disable automatic PDU processing
    central.enable_synchronous(True)

With the connector set in synchronous mode, every received PDU is then stored by
the connector in a dedicated queue and can be retrieved using 
:py:meth:`whad.device.connector.WhadDeviceConnector.wait_packet`.
This method requires the connector to be in synchronous mode and will return
a PDU from the connector's queue, or `None` if the queue is empty once the
specified timeout period expired.
