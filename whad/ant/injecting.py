"""
WHAD ANT injection configuration

This module defines the ANT configuration class for
packet injection.
"""
from dataclasses import dataclass

@dataclass
class InjectionConfiguration:
    """
    Configuration for injecting in an ANT communication.

    :param channel: select the channel to use (c)
    """
    channel : int = 0