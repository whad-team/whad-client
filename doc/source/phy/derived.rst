Derived PHY connectors
======================

Some additional connectors are available as they rely on existing modulations,
allowing easy configuration and usage.

LoRa connector
--------------

A :class:`whad.phy.connector.lora.LoRa` connector is available and acts as a
wrapper for the underlying LoRa modulation. This connector will automatically
enables this modulation but also provides methods to configure a LoRa receiver
or transmitter, as well as sniffing packets.

For instance, to configure a LoRa interface for sniffing:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.phy.connector.lora import LoRa

    # Create our device
    device = WhadDevice.create("uart0")

    # Create our LoRa connector
    lora = LoRa(device)

    # Configure our LoRa sniffer
    lora.sf = 7
    lora.cr = 45
    lora.bw = 250000
    lora.preamble_length = 12
    lora.syncword = b"\x12"
    lora.enable_crc(True)
    lora.enable_explicit_mode(True)

    # Start sniffing
    lora.start()

.. automodule:: whad.phy.connector.lora
    :members: