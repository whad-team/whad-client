Getting started with WHAD
=========================

Connecting a WHAD device
------------------------

WHAD provides a class called :class:`UartDevice` that is able to communicate with
any WHAD-enabled UART device. Make sure to plug a compatible device into your
computer and to get the corresponding device name (e.g. */dev/ttyUSB0*).

To connect to a WHAD device, simply instanciate an :class:`UartDevice` with the
following parameters:

.. code-block:: python

    from whad import UartDevice

    device = UartDevice('/dev/ttyUSB0')

This instance can communicate with the device, and you can get some information
about the device itself:

.. code-block:: python

    # Open the device
    device.open()
    
    # Discover device information and capabilities
    device.discover()

    # Display 
    print('firmware author: %s' % device.info.fw_author)
    print('firmware url: %s' % device.info.fw_url)

This will open the device, query the device and print the device firmware URL and author.

Usually, a WHAD device is just instanciated and given to a specific connector that will
handle a specific protocol or/and related attacks and features. 


Using connectors
----------------

Connectors are wireless protocol-specific classes that implement one or more behaviors.
WHAD provides different connectors for different protocols such as (non-exhaustive list):

* BLE Central role
* BLE Peripheral role
* BLE Sniffer

A connector is some kind of wrapper that will drive a specific device in order to
perform one or more specific actions. As an example, we are going to connect to
a BLE device using a dedicated connector, :class:`whad.domain.ble.connector.central.Central`.

First, we need to create a :class:`UartDevice` object and pass it to our connector:

.. code-block:: python

    from whad import UartDevice
    from whad.domain.ble import Central

    central = Central(UartDevice('/dev/ttyUSB0'))

By doing so, we have a `central` object that can be used to act as a BLE central device.
This specific connector also provides a pure python BLE stack that will drive our
WHAD-compatible device. Let ask our central to connect to a remote device.

.. code-block:: python

    target = central.connect('0C:B8:15:C4:88:8E')

By calling the `connect()` method, we initiate a BLE connection to the target BLE device
and receives in return an `PeripheralDevice` instance if connection has been successfully
established. *This behavior is specific to this connector class and may change when using
other connectors. Please refer to the connector documentation before using it.*

Once the connection established, we can use the `discover()` method to perform a GATT
discovery operation, enumerating all available services and characteristics:

.. code-block:: python

    target.discover()

Once done, we can read this device name:

.. code-block:: python

    device_name = target.get_characteristic(UUID('1800'), UUID('2A00'))
    if device_name is not None:
        print('Device name: %s' % device_name.value)

Last, we disconnect and close everything:

.. code-block:: python

    target.disconnect()
    central.stop()
    central.close()

And that's it, we have a tiny Python script that connects to a BLE device,
query its services and characteristics, read a specific characteristic and
terminate the connection:

.. code-block:: python

    from whad import UartDevice
    from whad.domain.ble import Central

    # Create a central device
    central = Central(UartDevice('/dev/ttyUSB0'))

    # Connect to our target device
    target = central.connect('0C:B8:15:C4:88:8E')

    # Discover services and characteristics
    target.discover()

    # Read device name
    device_name = target.get_characteristic(UUID('1800'), UUID('2A00'))
    if device_name is not None:
        print('Device name: %s' % device_name.value)
    else:
        print('No device name characteristic found')
    
    # Terminate connection and exit gracefully
    target.disconnect()
    central.stop()
    central.close()

Using tools
-----------

WHAD also provides specific tools through dedicated classes. These tools mostly
use specific connectors to implement high-level behaviors. As an example, we
will demonstrate the use of :class:`GattProxy` class. This class creates a BLE
proxy that will forward all GATT operations to a target device, and the results
to a client connected to a custom device managed by the proxy.

The :class:`GattProxy` class only requires two WHAD devices and a target BD
address as parameters. It will connect to the target device, query its services
and characteristics and then create a similar peripheral device that will
forward everything to the already connected device. 

.. code-block:: python

    from whad import UartDevice
    from whad.domain.ble.tools import GattProxy

    class MyProxy(GattProxy):

        def on_characteristic_read(self, service, characteristic, value, offset=0, length=0):
            """This method will be called each time a characteristic is read
            """
            print(' << characteristic %s from service %s read: %s' % (
                characteristic.uuid,
                service.uuid,
                value
            ))

        def on_characteristic_write(self, service, characteristic, offset=0, value=b'', without_response=False):
            """This method will be called each time a characteristic is written
            """
            print(' >> write to characteristic %s from service %s : %s' % (
                characteristic.uuid,
                service.uuid,
                value
            ))

        def on_characteristic_subscribe(self, service, characteristic, notification=False, indication=False):
            """This methiod will be called each time a characteristic is subscribed
            """
            print(' ** Subscribed to characteristic %s from service %s' % (
                characteristic.uuid,
                service.uuid
            ))

        def on_notification(self, service, characteristic, value):
            """This method will be called each time a notification is sent
            """
            print(' == Notification received from characteristic %s from service %s: %s' % (
                characteristic.uuid,
                service.uuid,
                value               
            ))

        def on_indication(self, service, characteristic, value):
            """This method will be called each time an indication is sent
            """
            print(' == Indication received from characteristic %s from service %s: %s' % (
                characteristic.uuid,
                service.uuid,
                value               
            ))

    proxy = MyProxy(
        UartDevice(periph_dev, 115200),
        UartDevice(central_dev, 115200),
        None,
        '0C:B8:15:C4:88:8E'
    )

    proxy.start()