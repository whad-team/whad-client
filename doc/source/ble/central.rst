Central role
============

.. py:currentmodule:: whad.ble.connector.central

Bluetooth Low Energy central role is used to connect to a BLE peripheral and
interact with it. WHAD provides a specific connector, :class:`Central`,
that implements this role.

It is possible to register a callback function to be called whenever an
asynchronous event is received by this connector using its :py:meth:`Central.add_event_handler`
method. This callback function will be called every time a central-related event is received.

A :py:class:`CentralConnected` event is sent when the
current Central connector has successfully connected to a device and a 
:py:class:`CentralDisconnected` event is sent when
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

Interacting with a remote Peripheral device
-------------------------------------------

The :py:class:`Central` connector can initiate a connection to
a remote device and implements a GATT client to interact with it once a connection
successfully established. Remote GATT services and characteristics can be
discovered through the corresponding GATT procedure, characteristics value can
be read and written and it is also possible to subscribe for notifications or
indications in order to be notified when the remote GATT server updates a
characteristic value.

Initiating a connection
^^^^^^^^^^^^^^^^^^^^^^^

This connector provides the :py:meth:`~.Central.connect` method
that initiates a connection to a specific device. A connection to a remote BLE
device that advertises itself with a public BD address can be initiated as shown
below:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.ble import Central

    # We assign a BLE central role to our HCI adapter
    central = Central(WhadDevice.create("hci0"))

    # And we initiate a connection to our public BLE device
    target = central.connect("00:11:22:33:44:55")

Calling :py:meth:`~.Central.connect` will set the hardware in
central mode, and it will listen for an advertisement from the specified device,
including its address type (in this case, a public address). If the specified
device cannot be found, a :py:exc:`.PeripheralNotFound` exception
is raised. The timeout used during this connection initiation can be specified
through the `timeout` parameter supported by the :py:meth:`~.Central.connect`
method:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.ble import Central

    # We assign a BLE central role to our HCI adapter
    central = Central(WhadDevice.create("hci0"))

    # And we initiate a connection to our public BLE device
    # with a timeout of 5 seconds
    target = central.connect("00:11:22:33:44:55", timeout=5.0)

.. note::

    The default timeout for connection initiation is 30 seconds.

When connecting to a device with a random address, the `random` parameter must
be specified to tell the :py:class:`Central` connector to look for a device with
a random address:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.ble import Central

    # We assign a BLE central role to our HCI adapter
    central = Central(WhadDevice.create("hci0"))

    # And we initiate a connection to our device that uses a random
    # address
    target = central.connect("00:11:22:33:44:55", random=True)

If a connection is successfully established, :py:meth:`~.Central.connect` returns
an instance of :py:class:`~whad.ble.profile.device.PeripheralDevice` that can be used
to interact with the remote GATT server.

In some very specific cases, we may want to set the *hop interval* value used when
initiating a connection in to optimize speed. The :py:meth:`~.Central.connect`
method accepts a `hop_interval` parameter that will be used as the *hop_interval*
value when initiating the connection:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.ble import Central

    # We assign a BLE central role to our HCI adapter
    central = Central(WhadDevice.create("hci0"))

    # And we initiate a connection to our device that uses a random
    # address
    target = central.connect("00:11:22:33:44:55", random=True, hop_interval=6)

.. important:: 
    
    Hop interval value must be comprised between 6 and 3200, as specified in the
    Bluetooth Specification in Vol 6, part B, section 4.5.1.

Enumerating remote services and characteristics
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Once connected to a remote device that implements a *peripheral* role, it is
possible to discover the exposed services, characteristics and descriptors by
starting a GATT discovery procedure:

.. code-block:: python

    # Discover remote services and characteristics
    target.discover()

Once this procedure is complete, the corresponding :py:class:`.PeripheralDevice`
instance is populated with the discovered services and characteristics. Discovered
services can then be listed with a call to :py:meth:`~.GenericProfile.services`,
that will yield each service as an instance of :py:class:`.PeripheralService`:

.. code-block:: python

    # List discovered services
    for service in target.services()
        print(f"- {service.name} (handle: {service.handle})")

We then can list each discovered characteristic from a given service by calling
the services's :py:meth:`~.PeripheralService.characteristics` method:

.. code-block:: python

    # List discovered services and characteristics
    for service in target.services()
        print(f"- {service.name} (handle: {service.handle})")
        for char in service.characteristics()
            print(f"  * {char.name} (handle: {char.handle})")

Eventually, it is possible to list each characteristic descriptor in a similar
fashion through a call to each characteristic's :py:meth:`PeripheralCharacteristic.descriptors`
method:

.. code-block:: python

    # List discovered services and characteristics
    for service in target.services()
        print(f"- {service.name} (handle: {service.handle})")
        for char in service.characteristics()
            print(f"  * {char.name} (handle: {char.handle})")
            for desc in char.descriptors():
                print(f"   desc: f{desc.name}")


Getting a characteristic object from its UUID
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The easiest way to interact with a remote GATT server, once its services and
characteristics discovered, is to get an instance of :py:class:`PeripheralCharacteristic`
from the connected peripheral. The :py:class:`PeripheralCharacteristic` class
exposes some methods to initiate different GATT operations on characteristics,
like reading or writing its value.

First, we need to retrieve a characteristic based on its UUID. Let's say we
want to read the remote device's name through the `DeviceName` characteristic
exposed by the `Generic Access` service. This characteristic is a standard one,
defined in the specification by the `0x2A00` 16-bit UUID, and is part of the
standard `Generic Access` service identified with the `0x1800` 16-bit UUID:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.ble import Central
    from whad.ble.exceptions import PeripheralNotFound
    from whad.ble.profile import UUID

    # We assign a BLE central role to our HCI adapter
    central = Central(WhadDevice.create("hci0"))

    try:
        # Connect to remote device and discover services and characteristics
        target = central.connect("00:11:22:33:44:55", random=True)
        target.discover()

        # Retrieve the DeviceName characteristic object
        device_name = target.get_characteristic(UUID(0x1800), UUID(0x2A00))
        print(device_name.name)

    # Device not found ?
    except PeripheralNotFound:
        print("Device not found.")

Providing the service and characteristic UUIDs is the cleanest way to get a
characteristic object, but the :py:class:`.PeripheralDevice` class also provides
a method to find a characteristic without providing its parent service's
UUID: :py:meth:`~.PeripheralDevice.find_characteristic_by_uuid`:

.. code-block:: python

    # Retrieve the DeviceName characteristic object
    device_name = target.find_characteristic_by_uuid(UUID(0x2A00))
    print(device_name.name)

This method returns the first characteristic that matches the provided UUID,
or `None` if no matching characteristic has been found.

Reading a characteristic value
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Once a characteristic object retrieved, its value can be read by simply
accessing its :py:attr:`.PeripheralCharacteristic.value` property:

.. code-block:: python

    # Reading the remote device name
    device_name = target.find_characteristic_by_uuid(UUID(0x2A00))
    print(device_name.value)

When this attribute is accessed, a GATT read operation is performed on the
corresponding characteristic's value handle and the response returned by
the remote GATT server is returned as the characteristic's value. Each access
to this attribute will perform a GATT read operation.

For characteristics containing long values, i.e values that are longer than the
ATT_MTU value used by the GATT server, the read operation performed when accessing
this attribute follows the Bluetooth specification and will read the characteristic's
value content piece by piece, and then return the whole value as a singe byte array,
in a transparent manner.

.. important::

    Calling :py:meth:`~.PeripheralCharacteristic.readable` before reading a characteristic
    to check if it is supposed to be read is a good idea as WHAD's BLE stack and
    GATT client implementation are flexible by design. A GATT read operation can
    be initiated against a characteristic advertised as non-readable and will lead
    to an exception being generated if the GATT server denies access.

    This flexibility also offers security researchers a way to test remote
    GATT servers implementation and possibly find inconsistencies between
    the discovered characteristics and the operations they support, like a
    non-readable characteristic that still can be read with a GATT read operation
    because of a missing check in the GATT server implementation ;)

Writing into a characteristic value
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Writing to a characteristic's value is quite as simple as reading it, we just
set the characteristic's value attribute and it starts a GATT write operation:

.. code-block:: python

    # Writing the remote device name
    # (don't do that, seriously, it's just an example)
    device_name = target.find_characteristic_by_uuid(UUID(0x2A00))
    device_name.value = b"pwnd"

Setting a characteristic's value will always trigger a GATT write operation, not
a GATT write command operation (a generic write operation causes the GATT server
to reply with the provided content to acknowledge a successful write, while a
GATT write command is just received by the GATT server but never acknowledged).

GATT write command operation can still be performed through a call to the 
:py:meth:`~.PeripheralCharacteristic.write` method provided by the :py:class:`.PeripheralCharacteristic`
class and setting its `without_response` parameter to `True`:

.. code-block:: python

    # Writing the remote device name through a write command operation
    device_name = target.find_characteristic_by_uuid(UUID(0x2A00))
    device_name.write(b"pwnd", without_response=True)

.. note::

    Characteristics with long values are automatically written using GATT prepared
    write requests.

.. important::

    Calling :py:meth:`~.PeripheralCharacteristic.writeable` before writing into
    a characteristic's value to check it accepts write requests is always a good
    idea.

    WHAD's BLE stack and GATT client are flexible by design and do not ensure a
    characteristic can be written before starting a GATT write operation and it
    could lead to an exception raised because the remote GATT server returned an
    error.

Checking support for notifications or indications
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some characteristics exposed by a GATT server support notifications or indications,
depending on the presence of a *ClientCharacteristicConfiguration* descriptor
(defined with type UUID 2902). Notifications and indications are one of the key
features of GATT to allow a GATT client to be notified when a characteristic's
value has changed. Both notifications and indications are sent by the remote
GATT server, but the latter requires a confirmation message sent by the GATT client
(see Vol 3. Part G, section 4.10 of the Bluetooth specification).

Both notifications and indications contain the characteristic's value (up to
`ATT_MTU - 3` bytes).

The :py:class:`.PeripheralCharacteristic` class provides two methods to respectively
check if a characteristic supports notifications or indications: :py:meth:`~.PeripheralCharacteristic.can_notify`
and :py:meth:`~.PeripheralCharacteristic.can_indicate`.

These methods only check if a characteristic has been declared with the correct
properties required to support notifications or indications, not if the corresponding
characteristics effectively own a *ClientCharacteristicConfiguration* descriptor
in their definition (required to subscribe for notifications or indications).

Subscribing for notifications
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A GATT server can send notifications or indications to GATT clients that have
subscribed for them by modifying the characteristic's associated *ClientCharacteristicConfiguration*
descriptor. This operation is implemented in the :py:meth:`~.PeripheralCharacteristic.subscribe`
method, and subscribing for notifications is pretty straightforward:

.. code-block:: python

    def notification_callback(characteristic, value: bytes, indication=False):
        """Process notifications sent by the GATT server

        :param  characteristic: Characteristic concerned by this notification
        :type   characteristic: whad.ble.profile.device.PeripheralCharacteristic
        :param  value: Characteristic's new value
        :type   value: bytes
        :param  indication: `True` if callback has been called from an indication
        :type   indication: bool
        """
        print(f"Characteristic {characteristic.name} value has been changed to {value.hex()}")

    # Subscribe for notification if characteristic supports it
    # and sets a callback
    device_name = target.find_characteristic_by_uuid(UUID(0x2A00))
    if device_name.can_notify():
        if device_name.subscribe(notification=True, callback=notification_callback):
            print(f"Succesfully subscribed for notifications for characteristic {device_name.uuid}")
        else:
            print(f"An error occured while subscribing for notifications.")

The provided callback function will be called each time a notification is received,
with the new characteristic's value. For notifications, its `indication` argument
is expected to be `False`.

Subscribing for indications
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Subscribing for indications is very similar:

.. code-block:: python

    def indication_callback(characteristic, value: bytes, indication=False):
        """Process notifications sent by the GATT server

        :param  characteristic: Characteristic concerned by this notification
        :type   characteristic: whad.ble.profile.device.PeripheralCharacteristic
        :param  value: Characteristic's new value
        :type   value: bytes
        :param  indication: `True` if callback has been called from an indication
        :type   indication: bool
        """
        assert indication
        print(f"Characteristic {characteristic.name} value has been changed to {value.hex()}")

    # Subscribe for indication if characteristic supports it
    # and sets a callback
    device_name = target.find_characteristic_by_uuid(UUID(0x2A00))
    if device_name.can_indicate():
        if device_name.subscribe(indication=True, callback=notification_callback):
            print(f"Succesfully subscribed for indications for characteristic {device_name.uuid}")
        else:
            print(f"An error occured while subscribing for indications.")

The provided callback function will be called each time a notification is received,
with the new characteristic's value. For notifications, its `indication` argument
is expected to be `True`.

Unsubscribing from notifications or indications
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Unsubscribing from a characteristic is the same for notifications and indications,
as the corresponding *ClientCharacteristicConfiguration* descriptor's value is
set to its default value (0x0000):

.. code-block:: python

    # Unsubscribe from notifications or indications
    if device_name.unsubscribe():
        print(f"Successfully unsubscribe from characteristic {device_name.uuid}")


Terminating the current connection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A connection to a remote peripheral can be terminated by calling its :py:meth:`~.PeripheralDevice.disconnect`
method:

.. code-block:: python

    # Terminate connection
    target.disconnect()


Handling GATT exceptions
------------------------

When performing various GATT operations against a GATT server, some errors might
be sent to the GATT client because of an invalid value used or simply because
a GATT operation requires authentication or authorization.

Each time such an error is encountered by WHAD's GATT client, an exception is
raised and must be caught and properly handled to avoid a brutal disconnection
due to an unhandled exception.

All GATT-related exceptions inherit from the :py:class:`~whad.ble.stack.att.exceptions.AttError`
class and can therefore be caught and processed quite easily. The following example
code shows how to handle GATT write errors:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.ble import Central
    from whad.ble.exceptions import PeripheralNotFound
    from whad.ble.profile import UUID
    from whad.ble.stack.att.exceptions import WriteNotPermittedError

    # We assign a BLE central role to our HCI adapter
    central = Central(WhadDevice.create("hci0"))

    # Target not connected
    target = None

    try:
        # Connect to remote device and discover services and characteristics
        target = central.connect("00:11:22:33:44:55", random=True)
        target.discover()

        # Writing into the remote device name (could fail)
        try:
            device_name = target.find_characteristic_by_uuid(UUID(0x2A00))
            device_name.value = b"p0wn3d"
        except WriteNotPermittedError:
            print("Device name characteristic cannot be written.")
        
        # Closing connection
        target.disconnect()
    
    # Handle connection error
    except PeripheralNotFound:
        print("Target device not found.")

    # Handle any other ATT errors
    except AttError as att_err:
        print("An unsupported ATT error has been raised:")
        print(att_err)

    # Handle CTL-C
    except KeyboardInterrupt:
        try:
            if target is not None:
                target.disconnect()
        except AttError:
            print("An error occured while disconnecting from target.")


Central connector and events
----------------------------

.. autoclass:: whad.ble.connector.Central
    :members:

.. autoclass:: whad.ble.connector.central.CentralConnected
    :members:

.. autoclass:: whad.ble.connector.central.CentralDisconnected
    :members:

Peripheral device abstraction
-----------------------------

.. automodule:: whad.ble.profile.device
    :members: PeripheralDevice, PeripheralService, PeripheralCharacteristic, PeripheralCharacteristicDescriptor, PeripheralCharacteristicValue
