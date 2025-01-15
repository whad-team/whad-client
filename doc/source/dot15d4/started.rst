Getting started
===============

IEEE 802.15.4 wireless protocol is widely used by some well-known protocols
such as ZigBee, RF4CE or 6LoWPAN.

WHAD provides a basic connector, :class:`whad.dot15d4.connector.Dot15d4`, to
handle IEEE 802.15.4 communications.

Sniffing packets
----------------

The :class:`whad.dot15d4.connector.sniffer.Sniffer` connector provides sniffing
capability for IEEE 802.15.4 packets. All we have to do is simply set the
channel and sniff packets:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.dot15d4 import Sniffer

    # Create a compatible device instance
    device = WhadDevice.create("uart0")

    # Use a sniffer connector
    sniffer = Sniffer(device)

    # Set channel
    sniffer.channel = 11

    # Start sniffing
    sniffer.start()

    # Listen for packets for 30 seconds
    for packet in sniffer.sniff(timeout=30.0):
        packet.show()

Sending packets
---------------

Sending IEEE 802.15.4 packets is as easy as it sounds, simply use the
:func:`whad.dot15d4.connector.Dot15d4.send` as follows:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.dot15d4 import Sniffer

    # Create a compatible device instance
    device = WhadDevice.create("uart0")

    # Use a default Dot15d4 connector
    connector = Dot15d4(device)

    # Send 802.15.4 packet
    connector.send(b"Hello World !")




