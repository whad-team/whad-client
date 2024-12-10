"""
WHAD Enhanced ShockBurst injection configuration

This module defines the ESB configuration class for
packet injection.
"""
from dataclasses import dataclass

@dataclass
class InjectionConfiguration:
    """
    Configuration for injecting in an Enhanced ShockBurst communication.

    :param channel: select the channel to use (c)
    :param address: provide address to use (f)
    :param synchronize: enable synchronization (s)
    """
    channel : int = 0
    address : str = None
    synchronize : bool = False
