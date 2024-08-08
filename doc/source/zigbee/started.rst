Getting started
===============

Zigbee protocol is based on IEEE 802.15.4 and therefore relies on our Dot15d4
domain.

Sniffing packets
----------------

Sniffing ZigBee packets is possible thanks to our dedicated sniffer
:class:`whad.zigbee.connector.sniffer` class. The following code captures
ZigBee frames sent on channel 11:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.zigbee import Sniffer

    # Create our whad device object
    device = WhadDevice.create("uart0")

    # Create our ZigBee sniffer instance
    sniffer = Sniffer(device)

    # Set channel
    sniffer.channel = 11

    # Sniff packets
    for packet in sniffer.sniff():
        packet.show()

Decrypting ZigBee packets on-the-fly while sniffing
---------------------------------------------------

The ZigBee sniffer can, when this feature is enabled, capture packets used to
exchange an encryption key and extract these keys in order to use them later
for decrypting other packets. This is done automatically and transparently by
the sniffer.

To enable this feature, simply set the sniffer's ``decrypt`` property to True:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.zigbee import Sniffer

    # Create our whad device object
    device = WhadDevice.create("uart0")

    # Create our ZigBee sniffer instance
    sniffer = Sniffer(device)

    # Set channel
    sniffer.channel = 11
    sniffer.decrypt = True

    # Sniff packets
    for packet in sniffer.sniff():
        packet.show()

Recovered keys can be accessed through the sniffer configuration structure:

.. code-block:: python

    # Get recovered keys
    print(sniffer.configuration.keys)

