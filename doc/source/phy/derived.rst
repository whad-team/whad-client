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

.. automodule:: whad.phy.connector.lora
    :members: