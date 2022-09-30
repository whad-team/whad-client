from dataclasses import dataclass

@dataclass
class SnifferConfiguration:
    """
    Configuration for sniffing a Zigbee communication.

    :param channel: select the channel to sniff (c)
    """

    channel : int = 11
