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
:class:`whad.ble.profile.GenericProfile` in which each *service*, its associated
*characteristics* and *descriptors* will be defined as default class properties.
These properties will be used to populate the corresponding GATT server attributes
database with each user-defined services, characteristics and descriptors.

The following code defines a simple GATT profile (defined by the 16-bit UUID 0x1800)
defining a *Generic Access Service* with its associated *DeviceName* characteristic
(defined by the 16-bit UUID 0x2A00):

.. code-block:: python

    from whad.ble.profile.attribute import UUID
    from whad.ble.profile import PrimaryService, Characteristic, GenericProfile

    class CustomProfile(GenericProfile):
        """Custom GATT profile"""

        # Define a generic access service (GAS) with UUID 0x1800
        gas = PrimaryService(
            uuid=UUID(0x1800),

            # Define a DeviceName characteristic with read/write permissions
            device_name = Characteristic(
                uuid=UUID(0x2A00),

                # Read/write permissions
                permissions=['read', 'write'],

                # Characteristic supports notifications with a
                # ClientCharacteristicConfiguration descriptor (CCCD)
                notify=True,

                # Default value for this characteristic
                value=b"TestDevice"
            )
        )

This custom GATT profile does not follow the Bluetooth Specifications and especially
its default *Generic Access Profile* (as defined in *Vol 3, Part C, Section 12*).

It is then possible to create an instance of :class:`Peripheral` using this custom
GATT profile class and specific advertising data, as follows:

.. code-block:: python
    from whad.ble import Peripheral
    from whad.ble.profile.advdata import AdvCompleteLocalName, AdvDataFieldList, AdvFlagsField
    from whad.ble.profile.attribute import UUID
    from whad.ble.profile import PrimaryService, Characteristic, GenericProfile
    from whad.device.uart import WhadDevice

    class CustomProfile(GenericProfile):
        """Custom GATT profile"""

        # Define a generic access service (GAS) with UUID 0x1800
        gas = PrimaryService(
            uuid=UUID(0x1800),

            # Define a DeviceName characteristic with read/write permissions
            device_name = Characteristic(
                uuid=UUID(0x2A00),

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
        WhadDevice.create("hci0"),
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



Bluetooth Low Energy Peripheral connector
-----------------------------------------

.. automodule:: whad.ble.connector
    :members: Peripheral

Bluetooth Low Energy Peripheral events
--------------------------------------

.. autoclass:: whad.ble.connector.peripheral.PeripheralEventConnected
    :members:

.. autoclass:: whad.ble.connector.peripheral.PeripheralEventDisconnected
    :members:
