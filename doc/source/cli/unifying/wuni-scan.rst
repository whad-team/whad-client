wuni-scan: Logitech Unifying device scanner
===========================================

``wuni-scan`` scans all the Logitech Unifying 2.4GHz channels and detects any device
communicating through the Logitech Unifying protocol (mostly keyboards and mice).
It is also able to follow a specific device across channels based on its address,
and display a dump of all packets sent with a quick analysis, whenever it is possible.


Usage
-----

.. code-block:: text

    wuni-scan -i <INTERFACE> [-c/--channel CHANNEL] [-a/--address ADDRESS]

A compatible WHAD *interface* is required to listen to packets transmitted by a
Logitech Unifying device. Channel (*CHANNEL*) and device address (*ADDRESS*) are
optional and will allow `wuni-scan` to better track a device and not miss a packet.

Searching for Logitech Unifying devices on any channel
------------------------------------------------------

To discover every Logitech Unifying devices around you, just start a basic scan
with the following command. The scanner will loop over all possible channels and
will report any Logitech Unifying packet sent by a device.

.. code-block:: text

    $ wuni-scan -i uart0
    Scanning for Unifying devices on channels 0-100 ...
    [014][29:b9:81:2c:a4] 00c2a40000bcdfff0000 | Mouse (movement)
    [014][29:b9:81:2c:a4] 00c2bf00000080ff0000 | Mouse (movement)
    [014][29:b9:81:2c:a4] 00c2190000f52f010000 | Mouse (movement)
    [014][29:b9:81:2c:a4] 00c24200000ef0fe0000 | Mouse (movement)
    [014][29:b9:81:2c:a4] 00c2db0000f46f000000 | Mouse (movement)
    [014][29:b9:81:2c:a4] 00c2bf00001070ff0000 | Mouse (movement)
    [014][29:b9:81:2c:a4] 00c23e0000f10f000000 | Mouse (movement)
    [014][29:b9:81:2c:a4] 004f5c00005500000000

In this example, a Logitech Unifying wireless mouse with address *29:b9:81:2c:a4*
using channel 14 has been discovered, sending movement data to its associated dongle.

.. note:: What should I do once I've discovered a device ?

    The scanner still loops over all the channels and will definitely misses
    some packets. It is highly recommended, once you've identified a device
    that you want to track, to start a targeted sniffing.


Sniffing packets from a specific device across channels
-------------------------------------------------------

If a device address is known, `wuni-scan` can find the channel it uses and follow
this device across all channels it may jump to. This mode may still miss some
packets especially when the target device switches to another channel, but is
far more reliable. The `--address` (or `-a`) option enables this following mode:

.. code-block:: text

    $  wuni-scan -i uart0 -a 29:b9:81:2c:a4
    Following device 29:b9:81:2c:a4 in auto mode ...
    [017][29:b9:81:2c:a4] 00c2bb0000f48f000000 | Mouse (movement)
    [017][29:b9:81:2c:a4] 00c24c0000f3ff000000 | Mouse (movement)
    [017][29:b9:81:2c:a4] 00c22b0000f31f010000 | Mouse (movement)
    [017][29:b9:81:2c:a4] 00c21000000e20000000 | Mouse (movement)
    [017][29:b9:81:2c:a4] 00c2660000f9df000000 | Mouse (movement)


Sniffing packets from a specific device on a single channel
-----------------------------------------------------------

You may also want to sniff packets on a single channel used by a target device,
therefore specifying this channel number with the `--channel` (or `-c`) along with
the `--address` (or `-a`) option will show any packet sent by the target device
on the specified channel:

.. code-block:: text

    $ wuni-scan -i uart0 -a 29:b9:81:2c:a4 -c 17
    Sniffing device 29:b9:81:2c:a4 on channel 17...
    [017][29:b9:81:2c:a4] 00c2410000ffffff0000 | Mouse (movement)
    [017][29:b9:81:2c:a4] 004f5c00005500000000 
    [017][29:b9:81:2c:a4] 00c27500000ac0ff0000 | Mouse (movement)
    [017][29:b9:81:2c:a4] 00c28500000ab0ff0000 | Mouse (movement)
    [017][29:b9:81:2c:a4] 00c25d000002e0ff0000 | Mouse (movement)
    [017][29:b9:81:2c:a4] 00c2520000feefff0000 | Mouse (movement)
    [017][29:b9:81:2c:a4] 00c2530000fdefff0000 | Mouse (movement)
    [017][29:b9:81:2c:a4] 00c2530000fdefff0000 | Mouse (movement)

