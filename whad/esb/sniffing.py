"""
WHAD Enhanced ShockBurst sniffing configuration

This module defines the ESB configuration class for
packet sniffing.
"""
from dataclasses import dataclass

@dataclass
class SnifferConfiguration:
    """
    Configuration for sniffing a Enhanced ShockBurst communication.

    :param channel: select the channel to sniff (c)
    :param address: provide address to sniff (f)
    :param scanning: enable scanning mode (s)
    :param acknowledgements: enable acknowledgements sniffing (a)
    """
    channel : int = 0
    address : str = "FF:FF:FF:FF:FF"
    scanning : bool = False
    acknowledgements : bool = False
