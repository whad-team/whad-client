"""Dot15d4 injection module

This module provides an Injector class for RF4CE protocol, that is used by
`winject` to inject RF4CE protocol.
"""
from typing import Generator, List

# Required by type hints
from scapy.packet import Packet

from whad.rf4ce.connector import RF4CE
from whad.rf4ce.injecting import InjectionConfiguration
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type

class Injector(RF4CE):
    """
    RF4CE Injector interface for compatible WHAD device.
    """

    def __init__(self, device):
        """Initialize our injector.
        """
        RF4CE.__init__(self, device)

        self.__configuration = InjectionConfiguration()

        # Check if device can perform injection
        if not self.can_send():
            raise UnsupportedCapability("Inject")

    @property
    def configuration(self) -> InjectionConfiguration:
        """Retrieve this injector configuration.
        """
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration: InjectionConfiguration):
        """Set the injector configuration.
        """
        self.__configuration = new_configuration

    @property
    def channel(self) -> int:
        """Retrieve the currently configured channel this injector will inject to.
        """
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel: int = 11):
        """Set current channel.
        """
        self.__configuration.channel = channel

    def inject(self, packet):
        if self.__configuration.channel is not None:
            channel = self.__configuration.channel
        elif hasattr(packet, "metadata") and hasattr(packet.metadata, "channel"):
            channel = packet.metadata.channel
        else:
            channel = 11 # fallback to channel 11
        super().send(packet, channel=channel)
