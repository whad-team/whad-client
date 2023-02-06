Built-in command-line tools
---------------------------

WHAD provides two types of command-line tools:

* generic command-line tools named in the form *whad<tool>*: these tools can
  be used with any WHAD device and may provide cross-protocol features or manage
  any WHAD device (**whadup** for instance)
* domain-specific tools named in the form of *<domain>-<tool>*: these tools can
  be used with any WHAD device that supports a specific domain (**ble-central**
  for instance)


Generic tools
~~~~~~~~~~~~~

* :doc:`whadup <whadup.rst>`: WHAD device management

Bluetooth Low Energy tools
~~~~~~~~~~~~~~~~~~~~~~~~~~

* :doc:`ble-central <ble-central>`: Scanner and GATT client
* :doc:`ble-periph <ble-periph>`: GATT server