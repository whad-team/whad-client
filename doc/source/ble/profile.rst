.. _whad-ble-device-model:

.. py:currentmodule:: whad.ble

Device Model
============

WHAD uses a specific device model to create BLE peripherals. This device model
is implemented in :class:`~whad.ble.Profile` and allows dynamic
modification of services and characteristics but also provides a convenient
way to define a device's services, characteristics and descriptors.

.. contents:: Table of Contents
   :local:

Creating a device model of a BLE peripheral
-------------------------------------------

Here is an example of a BLE peripheral implemented with WHAD:

.. code-block:: python

    from whad.ble import UUID, Profile, PrimaryService, Characteristic

    class MyPeripheral(Profile):

        generic_access = PrimaryService(
            UUID(0x1800),

            device_name = Characteristic(
                UUID(0x2A00),
                permissions=['read', 'notify'],
                value=b'My device name'
            )
        )


:class:`~.Profile` performs an introspection on its properties
to find every instance of :class:`~.PrimaryService`, finds every
instance of :class:`~.Characteristic` declared into each service
and populates its attribute database based on the discovered information.

But this mechanism also allows dynamic modification of any characteristic, for
instance the device name characteristic:

.. code-block:: python

    periph_inst = MyPeripheral()
    periph_inst.generic_access.device_name = b'Another name'

Of course, this can also be done when the peripheral is running and will cause
the BLE stack to send notifications or indications based on the characteristics
properties.


Hooking GATT events on characteristics
--------------------------------------

WHAD BLE device model provides a set of method decorators that must be used
to attach a method to a specific event and a specific characteristic:

* :class:`~.read` declares a characteristic read event handler
* :class:`~.write` declares a characteristic before-write event handler
* :class:`~.written` declares a characteristic after-write event handler
* :class:`~.subscribed` declares a characteristic subscribe event handler
* :class:`~.unsubscribed` declares a characteristic unsubscribe event handler

A characteristic event handler may raise one of the following exception to cause
the GATT stack to react accordingly:

* :class:`~.exceptions.HookReturnValue`: force a characteristic value to be returned
  to a GATT client on a read event
* :class:`~.exceptions.HookReturnGattError`: generates a GATT error that will
  be sent back to the connected GATT client
* :class:`~.exceptions.HookReturnNotFound`: tells a GATT client the characteristic
  does not exist
* :class:`~.exceptions.HookReturnAccesDenied`: tells a GATT client that
  authentication is required to access this characteristic

If no exception is raised in the event handler, the GATT operation continues as
expected. As an example, here follows a peripheral model declaration that uses
a characteristic event handler:

.. code-block:: python

    class MyPeripheral(Profile):

        generic_access = PrimaryService(
            UUID(0x1800),

            device_name = Characteristic(
                UUID(0x2A00),
                permissions=['read', 'write', 'notify'],
                value=b'My device name'
            )
        )

        @read(generic_access.device_name)
        def on_device_name_read(self, offset, mtu):
            """Return the content of the device name characteristic prefixed with 'FOO'
            """
            raise HookReturnValue(b'FOO'+ self.generic_access.device_name.value)

        @written(generic_access.device_name)
        def on_device_name_changed(self, value, without_response):
            """Called every time the device name characteristic has been changed by client.
            """
            print(f"Device name has been changed to: {value}")


GATT Profile API
----------------

.. autoclass:: whad.ble.UUID
    :members:

    .. automethod:: __init__

.. autoclass:: whad.ble.read

.. autoclass:: whad.ble.write

.. autoclass:: whad.ble.written

.. autoclass:: whad.ble.subscribed

.. autoclass:: whad.ble.unsubscribed

.. autoclass:: whad.ble.Profile
    :members:

    .. automethod:: __init__

.. autoclass:: whad.ble.Service
    :members:

    .. automethod:: __init__


.. autoclass:: whad.ble.PrimaryService
    :members:

    .. automethod:: __init__

.. autoclass:: whad.ble.SecondaryService
    :members:

    .. automethod:: __init__

.. autoclass:: whad.ble.IncludeService
    :members:

    .. automethod:: __init__

.. autoclass:: whad.ble.Characteristic
    :members:

    .. automethod:: __init__

.. autoclass:: whad.ble.Descriptor
    :members:
    
    .. automethod:: __init__

.. autoclass:: whad.ble.ClientCharacteristicConfig
    :members:
    
    .. automethod:: __init__

.. autoclass:: whad.ble.UserDescription
    :members:
    
    .. automethod:: __init__

Deprecated
^^^^^^^^^^

.. autoclass:: whad.ble.GenericProfile
    :members:

    .. automethod:: __init__

