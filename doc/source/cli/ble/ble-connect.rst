wble-connect: Connect to a BLE device
=====================================

``wble-connect`` initiates a connection to a remote BLE device and is intended to
be used in a packet processing chain. Once connected, it relays any PDU from the
device to any chained WHAD tool and any PDU from a chained tool to the device.


Usage
-----

.. code-block:: text

    wble-connect [OPTIONS] TARGET_BD_ADDRESS

Command-line options
--------------------

**ble-proxy** supports the following options:

* ``--interface`` (``-i``): specifies the WHAD interface to use to connect to the target device
* ``--no-color``: disables colors in output
* ``--spoof-public``: if supported, sets WHAD adapter's BD address to the specified public address
* ``--spoof-random``: if supported, sets WHAD adapter's BD address to the specified random address
* ``--random`` (``-r``): target device BD address is random (default: public)


Example usage
-------------

The following example shows a pretty simple usage of `wble-connect` combined with `wble-central`:

.. code-block:: text

    
    # wble-connect -i hci0 -r 40:d8:81:a1:a7:82 | wble-central read 3
    00000000: 4A 61 62 72 61 20 45 6C  69 74 65 20 37 35 74     Jabra Elite 75t

