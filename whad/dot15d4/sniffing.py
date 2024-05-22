from dataclasses import dataclass, field

@dataclass
class SnifferConfiguration:
    """
    Configuration for sniffing a 802.15.4 communication.

    :param channel: select the channel to sniff (c)

    """
    channel : int = 11
