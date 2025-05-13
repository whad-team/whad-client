Exceptions
==========

WHAD BLE domain exceptions
--------------------------

These exceptions are raised by Bluetooth Low Energy connectors and other related
classes to notify the main Python code that something unexpected happened and
must be taken care of.

.. automodule:: whad.ble.exceptions
    :members:
    :no-index:
    :exclude-members: HookDontForward, HookReturnValue, HookReturnGattError, HookReturnNotFound, HookReturnAccessDenied, HookReturnAuthentRequired, HookReturnAuthorRequired


BLE ATT exceptions
------------------

These exceptions are raised by WHAD's BLE stack when an error has been encountered during
a specific GATT operation. 

.. automodule:: whad.ble.stack.att.exceptions
    :no-index:
    :members: 

Hooking exceptions
------------------

These exceptions are used to force WHAD's BLE stack to behave specifically when
they are raised in a hook, like forcing a specific value to be returned when a
characteristic is read or force a GATT client to authenticate before accessing
a specific characteristic. 

Exceptions are used in this specific case as a way to divert from the expected
behavior and force the BLE stack to return a specific response to a GATT server.
This is not really how exceptions are designed for, but it does improve hooks
readability.

.. automodule:: whad.ble.exceptions
    :no-index:
    :members: HookDontForward, HookReturnValue, HookReturnGattError, HookReturnNotFound, HookReturnAccessDenied, HookReturnAuthentRequired, HookReturnAuthorRequired