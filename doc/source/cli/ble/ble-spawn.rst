wble-spawn: Spawn a BLE device
==============================

``wble-spawn`` creates a BLE device with a specific GATT profile and relays every
GATT operation to a real BLE device. This tool is intended to be used at the end
of a processing chain.

Usage
-----

.. code-block:: text

    wble-spawn -i <INTERFACE> -p [PROFILE]

A compatible WHAD *interface* and the path to a JSON *profile* are required to
populate the BLE device with the corresponding services and characteristics. It
will also allow `wble-spawn` to use the same advertising data, in order to make
the emulated device appear the same way the original does.

Example
-------

The following example first creates a JSON profile file using :ref:`wble-central <whad-wble-central>`,
then connects to the same device, launches *Wireshark* to monitor BLE packets and spawns a
device based on the `mydevice.json` profile.

All the data exchanged between a central device that connects to the emulated peripheral
will be logged by *Wireshark*.

.. code-block:: text

    # wble-central -i hci0 -b 11:22:33:44:55:66 profile mydevice.json
    # wble-connect -i hci0 11:22:33:44:55:66 | wshark | wble-spawn -i hci1 -p mydevice.json

