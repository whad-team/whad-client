"""ZigBee injection module

This module provides an Injector class for ZigBee protocol, that is used by
`winject` to inject ZigBee protocol.
"""
from typing import Generator, List

# Required by type hints
from scapy.packet import Packet

from whad.zigbee import Zigbee
from whad.zigbee.injecting import InjectionConfiguration
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type

class Injector(Zigbee):
    """
    ZigBee Injector interface for compatible WHAD device.
    """

    def __init__(self, device):
        """Initialize our injector.
        """
        Zigbee.__init__(self, device)

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
