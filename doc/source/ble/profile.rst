Bluetooth Low Energy Device Model
=================================

WHAD uses a specific device model to create BLE peripherals. This device model
is implemented in :class:`whad.ble.profile.GenericProfile` and allows dynamic
modification of services and characteristics but also provides a convenient
way to define a device services and characteristics.

Creating a device model of a BLE peripheral
-------------------------------------------

Here is an example of a BLE peripheral implemented with WHAD:

.. code-block:: python

    from whad.ble import UUID
    from whad.ble.profile import GenericProfile, PrimaryService, \
        Characteristic

    class MyPeripheral(GenericProfile):

        generic_access = PrimaryService(
            uuid=UUID(0x1800),

            device_name = Characteristic(
                uuid=UUID(0x2A00),
                permissions=['read', 'notify'],
                notify=True,
                value=b'My device name'
            )
        )


:class:`whad.ble.profile.GenericProfile` performs an introspection on its properties
to find every instance of :class:`whad.ble.profile.PrimaryService`, finds every
instance of :class:`whad.ble.profile.Characteristic` declared into each service
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

* :class:`whad.ble.profile.read` declares a characteristic read event handler
* :class:`whad.ble.profile.write` declares a characteristic before-write event handler
* :class:`whad.ble.profile.written` declares a characteristic after-write event handler
* :class:`whad.ble.profile.subscribed` declares a characteristic subscribe event handler
* :class:`whad.ble.profile.unsubscribed` declares a characteristic unsubscribe event handler

A characteristic event handler may raise one of the following exception to cause
the GATT stack to react accordingly:

* :class:`whad.ble.exceptions.HookReturnValue`: force a characteristic value to be returned
  to a GATT client on a read event
* :class:`whad.ble.exceptions.HookReturnGattError`: generates a GATT error that will
  be sent back to the connected GATT client
* :class:`whad.ble.exceptions.HookReturnNotFound`: tells a GATT client the characteristic
  does not exist
* :class:`whad.ble.exceptions.HookReturnAccesDenied`: tells a GATT client that
  authentication is required to access this characteristic

If no exception is raised in the event handler, the GATT operation continues as
expected. As an example, here follows a peripheral model declaration that uses
a characteristic event handler:

.. code-block:: python

    class MyPeripheral(GattProfile):

        generic_access = PrimaryService(
            uuid=UUID(0x1800),

            device_name = Characteristic(
                uuid=UUID(0x2A00),
                permissions=['read', 'write', 'notify'],
                notify=True,
                value=b'My device name'
            )
        )

        @read(generic_access.device_name)
        def on_device_name_read(self, service, charac, offset, mtu):
            """Return the content of the device name characteristic prefixed with 'FOO'
            """
            raise HookReturnValue(b'FOO'+ self.generic_access.device_name.value)

        @written(generic_access.device_name)
        def on_device_name_changed(self, service, charac, offset, value, without_response):
            """Called every time the device name characteristic has been changed by client.
            """
            print('Device name has been changed to: %s' % value)



GATT Generic Profile
--------------------

.. autoclass:: whad.ble.profile.GenericProfile
    :members:

    .. automethod:: __init__


GATT Primary service
--------------------

.. autoclass:: whad.ble.profile.PrimaryService
    :members:

    .. automethod:: __init__


GATT Characteristic
-------------------

.. autoclass:: whad.ble.profile.Characteristic
    :members:

    .. automethod:: __init__
