Built-in command-line tools
===========================

WHAD provides two types of command-line tools:

* generic command-line tools named in the form *whad<tool>*: these tools can
  be used with any WHAD device and may provide cross-protocol features or manage
  any WHAD device (**whadup** for instance)
* domain-specific tools named in the form of *<domain>-<tool>*: these tools can
  be used with any WHAD device that supports a specific domain (**ble-central**
  for instance)

.. toctree::
    :maxdepth: 1
    :caption: Bluetooth Low Energy tools

    ble/ble-central
    ble/ble-periph