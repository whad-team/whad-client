"""Basic WHAD message list replay Mock device.

This mock device takes a list of WHAD messages to send with an optional delay,
and will send them to the connector at the specified pace, without interaction.
"""
import logging
from time import sleep

from scapy.all import Packet, rdpcap

# Load WHAD dedicated layers
from whad.scapy.layers import *
from whad.hub.discovery import Domain

from whad.exceptions import WhadDeviceDisconnected
from .base import MockDevice


logger = logging.getLogger(__name__)

class ReplayMock(MockDevice):
    """Replay a series of WHAD messages and wait a given time between each message.
    """

    def __init__(self, *args, messages: list = None, delay:float = None,
                 domain: str = None, **kwargs):
        """Constructor."""
        super().__init__(*args, **kwargs)
        if isinstance(delay, int):
            delay = float(delay)
        elif not isinstance(delay, float):
            logger.warning("[%s] specified delay is not a floating-point number, assuming no delay",
                           self.interface)

        self.__delay = delay if isinstance(delay, float) else None
        self.__messages = [] if messages is None else messages

    @property
    def interface(self) -> str:
        """Mock interface alias for debugging."""
        return f"mock-replay{self.index}"

    def on_interface_message(self):
        """Each time this method is called, we wait `ifs` seconds and report
        a packet. If no more packet is available, we report this device as
        disconnected.
        """
        if len(self.__messages) > 0:
            if self.__delay is not None:
                sleep(self.__delay)
            return self.__messages.pop(0)
        else:
            raise WhadDeviceDisconnected()
