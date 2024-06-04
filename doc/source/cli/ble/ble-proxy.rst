.. _whad-ble-proxy:

ble-proxy: Bluetooth Low Energy GATT and Link-layer Proxy
=========================================================

``ble-proxy`` provides a basic tool to proxify a BLE connection and monitor traffic
between both devices. This tool must be used with two WHAD devices supporting the
*Bluetooth Low Energy* domain.

.. contents:: Table of Contents
    :local:
    :depth: 1

Usage
-----

.. code-block:: text

    ble-proxy [OPTIONS] BDADDR

``ble-proxy`` accepts one or more options and requires the target BD address.

Command-line options
--------------------

**ble-proxy** supports the following options:

* ``--interface`` (``-i``): specifies the WHAD interface to use to connect to the target device
* ``--no-color``: disables colors in output
* ``--proxy-interface`` (``-p``): specifies the WHAD interface to use for the emulated device
* ``--timeout`` (``-t``): specifies the timeout (in seconds) used for target device discovery
* ``--wireshark`` (``-w``): spawns a wireshark instance that will monitor packets in real-time
* ``--spoof`` (``-s``): enable BD address spoofing, if the proxy WHAD interface supports it
* ``--link-layer``: enable link-layer mode (default mode is GATT)
* ``--output`` (``-o``): specifies a target PCAP file in which all exchanged packets will be saved


Create a GATT proxy and monitor traffic
---------------------------------------

``ble-proxy`` default mode is GATT, meaning it will use its default WHAD interface (specified
with the ``--interface`` option) to look for a target device and connect to it, and then create
an emulated BLE device exposed on a second interface (specified with ``--proxy-interface``) that
will have the exact same services and characteristics.

This proxy will catch any GATT read, write, notification or indication relative to a specific
characteristic and will relay it to the target device. Packets will be monitored in real-time
in a Wireshark instance if enabled, or saved in a PCAP file if an output path is provided 
with the ``--output`` option.

The following command line will create a BLE GATT proxy using interface ``uart0`` to search and
connect to the target device and then emulate a BLE peripheral on the proxy interface ``hci0``.
A wireshark instance will be created since the ``--wireshark`` option is specified, and a packet
dump will be saved into the provided output file.

.. code-block:: text

    $ ble-proxy -i uart0 -p hci0 --wireshark --output /tmp/capture.pcap a4:c1:38:55:3d:11
    Scanning for target device (timeout: 30 seconds)...
    Proxy is ready, press a key to stop.
    Remote device connected
    >>> Characteristic 2A00 written
    00000000: 45 53 4D 4C 6D 5F 63 39  69 00                    ESMLm_c9i.
    >>> Characteristic 2A01 written
    00000000: 00 00                                             ..
    >>> Characteristic 00010203-0405-0607-0809-0a0b0c0d1911 written
    00000000: 46 4F 4F 42 41 72                                 FOOBAr
    Remote device disconnected



Create a Link-layer proxy and monitor traffic
---------------------------------------------

``ble-proxy`` also provides a link-layer mode that works quite differently from its default
GATT mode. In GATT mode, ``ble-proxy`` connects to the target device, enumerates its
services and characteristics and use this information to create a new emulated BLE peripheral
with the exact same profile. In link-layer mode however, ``ble-proxy`` directly forward
BLE PDUs from one device to another, avoiding this services and characteristics discovery
process. This link-layer mode offers better performances than GATT mode, but the output of
``ble-proxy`` will be harder to read as there is no interpretation of the data exchanged between
the target device and the client connected to the emulated device.


.. code-block:: text

    $ ble-proxy -i uart0 -p hci0 --wireshark --output /tmp/capture.pcap --link-layer a4:c1:38:55:3d:11
    Proxy is ready, press a key to stop.
    >>> Data PDU
    00000000: 0A 10 0C 00 05 00 12 01  08 00 12 00 22 00 00 00  ............"...
    00000010: C8 00                                             ..
    Remote device connected
    <<< Data PDU
    00000000: 02 10 0C 00 05 00 12 01  08 00 12 00 22 00 00 00  ............"...
    00000010: C8 00                                             ..
    <<< Data PDU
    00000000: 02 0B 07 00 04 00 08 01  00 FF FF 3A 2B           ...........:+
    [...]
    <<< Data PDU
    00000000: 02 07 03 00 04 00 0A 03  00                       .........
    >>> Data PDU
    00000000: 06 0F 0B 00 04 00 0B 45  53 4D 4C 6D 5F 63 39 69  .......ESMLm_c9i
    00000010: 00                                                .
    Remote device disconnected