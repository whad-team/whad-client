from dataclasses import dataclass, field
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY

@dataclass
class SnifferConfiguration:
    """
    Configuration for sniffing an ANT communication.

    :param channel: select the channel to sniff (c)
    :param network_key: provide network key (k)
    :param device_number: filter a specific device number (dn)
    :param device_type: filter a specific device type (dp)
    :param addresses: filter a specific transmission type (tt)
    """
    channel : int = 57
    device_number : int = 0
    device_type : int = 0
    transmission_type : int = 0
    network_key : bytes = ANT_PLUS_NETWORK_KEY