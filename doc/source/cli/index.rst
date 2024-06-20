Command-line tools
==================

WHAD provides two types of command-line tools:

* generic command-line tools named in the form *whad<tool>*: these tools can
  be used with any WHAD device and may provide cross-protocol features or manage
  any WHAD device (**whadup** for instance)

* domain-specific tools named in the form of *<domain>-<tool>*: these tools can
  be used with any WHAD device that supports a specific domain (**ble-central**
  for instance)


Tool chaining
-------------

WHAD provides a way to chain tools in order to create complex behaviors, to enable
tool modularity or simply to let the user arrange them to reach a specific goal.
The shell operator `|` is used to perform this chaining, as shown in the example
below:

.. code-block:: text

    $ ble-connect -i hci1 11:22:33:44:55:66 | ble-wireshark | ble-central profile

In this example, `ble-connect` will initiate a connection to the device identified
by the Bluetooth Device address `11:22:33:44:55:66`, spawn a wireshark that will
monitor every Bluetooth Low Energy packet sent or received thanks to `ble-wireshark`,
and then use `ble-central` to enumerate the target services and characteristics.


Tools provided by WHAD
----------------------

Generic tools
~~~~~~~~~~~~~

.. toctree::
    :maxdepth: 1

    generic/whadup


Bluetooth Low Energy
~~~~~~~~~~~~~~~~~~~~

.. toctree::
    :maxdepth: 1

    ble/ble-central
    ble/ble-periph
    ble/ble-wireshark
    ble/ble-proxy
    ble/ble-spawn

Logitech Unifying
~~~~~~~~~~~~~~~~~

.. toctree::
    :maxdepth: 1

    unifying/wuni-scan
