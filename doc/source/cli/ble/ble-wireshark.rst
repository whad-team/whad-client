ble-wireshark: monitor BLE packets
==================================

``ble-wireshark`` provides a very convenient way to monitor BLE packets (or PDU)
sent and received by a BLE-enable WHAD adapter. 

Usage
-----

.. code-block:: text

    ... | ble-wireshark | ...

``ble-wireshark`` can be used in a processing chain to monitor the BLE packets
exchanged between two chained tools. It will start `wireshark` and feed it the
captured packerts with a dedicated FIFO, providing a way to monitor in real-time
what is going on with a device. The following command line initiates a connection
to a device and discover its services and characteristics while monitoring all
the packets exchanged:

.. code-block:: text

    # ble-connect -i hci0 11:22:33:44:55:66 | ble-wireshark | ble-central profile

