Peripheral role
===============

.. py:currentmodule:: whad.ble.connector.peripheral

Bluetooth Low Energy peripheral role is used to create a BLE peripheral that accepts
connections from a Central device and exposes a GATT server. WHAD provides a specific
connector to create a BLE device, :class:`Peripheral`, that implements this role.
A custom GATT profile class derived from :class:`whad.ble.profile.GenericProfile`
needs to be defined and provided as a parameter when instantiating a :class:`Peripheral`
object.

The :class:`Peripheral`  connector allows to register a single event listener of class 
:py:class:`PeripheralEventListener` through its 
:py:meth:`Peripheral.attach_event_listener` method. This event listener must
be created with a callback function attached that will be called by the connector to
notify any connection or disconnection event (respectively a 
:py:class:`whad.ble.connector.peripheral.PeripheralEventConnected` and 
:py:class:`whad.ble.connector.peripheral.PeripheralEventDisconnected` instance).

.. important::

    The mechanism used to handle asynchronous events like connection and disconnection
    is still a work in progress. It has been introduced in a recent update to better
    handle connection and disconnection events and is not yet intended to be used
    by anything other WHAD's internal code.

    We have a full rework of WHAD's internals planned, including BLE Central and Peripheral
    classes, that will definitely bring some changes to the way connectors work. We will do
    our best not to break the current implementation.

Creating a basic Bluetooth Low Energy Peripheral device
-------------------------------------------------------

First, a custon GATT profile is defined as a class deriving from
:class:`~whad.ble.profile.Profile` in which each *service*, its associated
*characteristics* and *descriptors* will be defined as default class properties.
These properties will be used to populate the corresponding GATT server attributes
database with each user-defined services, characteristics and descriptors.

The following code defines a simple GATT profile (defined by the 16-bit UUID 0x1800)
defining a *Generic Access Service* with its associated *DeviceName* characteristic
(defined by the 16-bit UUID 0x2A00):

.. code-block:: python

    from whad.ble.profile import UUID, Profile, PrimaryService, Characteristic

    class CustomProfile(Profile):
        """Custom GATT profile"""

        # Define a generic access service (GAS) with UUID 0x1800
        gas = PrimaryService(
            UUID(0x1800),

            # Define a DeviceName characteristic with read/write permissions
            device_name = Characteristic(
                UUID(0x2A00),

                # Read/write/notify permissions
                permissions=['read', 'write', 'notify'],

                # Default value for this characteristic
                value=b"TestDevice"
            )
        )

This custom GATT profile does not follow the Bluetooth Specifications and especially
its default *Generic Access Profile* (as defined in *Vol 3, Part C, Section 12*).

It is then possible to create an instance of :class:`Peripheral` using this custom
GATT profile class and specific advertising data, as follows:

.. code-block:: python

    from whad.device import Device
    from whad.ble import (
        Peripheral, AdvCompleteLocalName, AdvDataFieldList, AdvFlagsField, UUID,
        PrimaryService, Characteristic, GenericProfile,
    )

    class CustomProfile(Profile):
        """Custom GATT profile"""

        # Define a generic access service (GAS) with UUID 0x1800
        gas = PrimaryService(
            UUID(0x1800),

            # Define a DeviceName characteristic with read/write permissions
            device_name = Characteristic(
                UUID(0x2A00),

                # Read/write permissions
                permissions=['read', 'write'],

                # Characteristic supports notifications with a
                # ClientCharacteristicConfiguration descriptor (CCCD)
                notify=True,

                # Default value for this characteristic
                value=b"TestDevice"
            )
        )

    # Create an instance of Peripheral class using HCI device hci0 and a custom
    # profile defined in CustomProfile
    profile = CustomProfile()
    peripheral = Peripheral(
        Device.create("hci0"),
        profile=profile,
        adv_data=AdvDataFieldList(
            AdvFlagsField(), # Defines a default Flags record
            AdvCompleteLocalName(b"TestDevice") # Adds a CompleteLocalName record
        )
    )

Starting and using a custom Peripheral device
---------------------------------------------

The previously created ``peripheral`` is completely defined and ready to be started
by calling its :py:meth:`Peripheral.start` method:

.. code-block:: python

    peripheral.start()

WHAD will advertise a Bluetooth Low Energy Peripheral device using the specified
advertising data, wait for a connection from a Central device and once established
will expose a GATT server interacting with the custom profile associated with it.

The peripheral's characteristics's values can be accessed from both a remotely
connected Central device and the main application that created this peripheral
device. These two possibilities are detailed hereafter.

Updating a custom profile's characteristic value from the main application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Changing a characteristic value from the main application is possible by simply
using the profile instance passed to the :class:`Peripheral`'s constructor.

In the custom profile defined above, the main application can access the
*DeviceName* characteristic by using the dynamically populated properties,
as shown below:

.. code-block:: python

    profile.gas.device_name.value = b"NewDeviceName"

Writing into the mapped characteristic value object causes the associated GATT
attribute to be updated with the provided value. If the corresponding characteristic
accepts notifications and the GATT client connected to the peripheral device has
subscribed for notifications, a notification is automatically sent by the Peripheral
device to the connected Central devicem no matter if the written value differs or not
from the previous one. If a Central device has subscribed for indications, an
indication is sent to the Central device instead of a notification.

The above example relies on the fact the GATT profile class defines its
characteristic using WHAD's Device Model feature (see :ref:`whad-ble-device-model`),
but some profile instances are created either from a JSON profile or
dynamically populated, with no specific property defined. In this case,
accessing a characteristic and updating its value is a bit more complex:

.. code-block:: python

    generic_service = profile.service('1800')
    if generic_service is not None:
        dev_name = battery_service.char('2a00'))
        dev_name.value = b"NewDeviceName"

If the Central device has subscribed for notifications or indications,
a notifcation or indication will be sent once the characteristic's value
has been modified.

Reacting on specific GATT events for a service's characteristic
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Any custom GATT profile class inheriting from :class:`~whad.ble.profile.Profile`
can use a set of specifically designed *decorators* to declare a method as a handler
for a GATT event related to a specific characteristic. The :class:`~whad.ble.profile.read`
decorator for instance can be used to intercept any read operation on a specific characteristic,
like in the following example code:

.. code-block:: python

    from whad.device import Device
    from whad.ble import (
        Peripheral, Profile, read, BatteryService, AdvCompleteLocalName,
        AdvDataFieldList, AdvFlagsField,
    )

    class BatteryDevice(Profile):
        """Device exposing a battery service
        """

        battery = BatteryService()

        @read(battery.level)
        def on_battery_level_read(self, offset, length):
            level = self.battery.percentage - 10
            if level <= 0:
                level = 100
            self.battery.percentage = level
            return self.battery.level.value

In this example code, we define a new `BatteryDevice` class inheriting
from :class:`~whad.ble.profile.Profile` and add a standard *Battery Service*
defined by :class:`~whad.ble.profile.BatteryService`. This
generic service adds its own characteristics as specified in
the `Bluetooth Battery Service specification <https://www.bluetooth.com/specifications/specs/html/?src=BAS_v1.1/out/en/index-en.html>`_
as well as dedicated properties to retrieve and set the corresponding battery
level as a percentage.

A custom GATT read event handler is defined for this profile's battery level
characteristic (identified by UUID `0x2A19` within the corresponding battery service
identified by UUID `0x180F`), thanks to the :class:`~whad.ble.profile.read` decorator.
The argument passed to this decorator is declared within the :class:`~whad.ble.profile.BatteryService`
class as `level` and can be used to identify a specific
characteristic belonging to the GATT model defined within any :class:`~whad.ble.profile.Profile`
class. Basically, any characteristic defined in a GATT profile class can be passed to this
decorator.

The decorated method, ``on_battery_level_read()`` accepts two parameters specifying the
offset and length required by the GATT read operation and *shall* be used to return
any partial value required by a Central device. In this example, we don't care about
any offset or length because most of the Central devices will read this characteristic
without using a GATT LongRead procedure (the characteristic value is stored on a single
byte), but a better implementation would take care of it to properly handle errors.
In our implementation, we first retrieve the current battery level from the characteristic's
value, decrements this value by 10 (setting it back to 100 if it reaches 0 or below),
write this value into the characteristic's value and return the updated characteristic value.
This method is always called before WHAD's BLE stack returns any value to the Central
device that initiated this GATT read operation, allowing to change the behavior of the
peripheral when needed.

In case a GATT profile has been dynamically populated from a JSON profile file, overriding
:class:`~whad.ble.profile.Profile`'s GATT operation handlers is the best way to
intercept any operation and modify the profile instance accordingly. The following methods
can be overriden to intercept different GATT operations:

- :py:meth:`~whad.ble.profile.Profile.on_characteristic_read`: this method is called
  when a GATT read operation is about to be peformed by WHAD's BLE stack and is in charge of
  calling any registered handler regarding the characteristic that is about to be read
- :py:meth:`~whad.ble.profile.Profile.on_characteristic_write`: this method is called
  when a GATT write operation is requested by a Central device *before* writing to the destination
  characteristic's value
- :py:meth:`~whad.ble.profile.Profile.on_characteristic_written`: this method is called
  when a GATT write operation has just been performed, to allow post-processing
- :py:meth:`~whad.ble.progile.Profile.on_characteristic_subscribed`: this method is called
  when a Central device has just subscribed to a characteristic for notification or indication
- :py:meth:`~whad.bleprofile.Profile.on_characteristic_unsubscribed`: this method is
  called when a Central device has just unsubscribed from a characteristic

If one or many of these methods are redefined (overriden) in a child class inheriting from
:class:`~whad.ble.profile.Profile`, calling the parent class implementation with ``super()``
is *mandatory*:

.. code-block:: python

    class MyChildClass(Profile):

        def on_characteristic_read(self, service: Service, characteristic: Characteristic, offset: int = 0, length: int = 0):
            """Hook for GATT read operation"""

            # Call parent method
            super().on_characteristic_read(service, characteristic, offset=offset, length=length)

            # Continue with custom processing (Forcing characteristic value)
            raise HookReturnValue(b"Oops")

Python API for Peripheral Role
------------------------------

The Bluetooth Low Energy peripheral role is provided by the :class:`Peripheral` connector class, inheriting from
the :class:`~whad.ble.connector.BLE` default connector.

Bluetooth Low Energy Peripheral connector
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: whad.ble.connector.peripheral.Peripheral
    :members:

Bluetooth Low Energy Peripheral events
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: whad.ble.connector.peripheral.PeripheralEventConnected
    :members:

.. autoclass:: whad.ble.connector.peripheral.PeripheralEventDisconnected
    :members:
