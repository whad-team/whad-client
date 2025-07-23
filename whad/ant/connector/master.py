import logging
from typing import Generator
from time import time

from scapy.packet import Packet

from whad.ant.connector import ANT
from whad.ant.stack import ANTStack
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type
from whad.hub.ant import RawPduReceived, PduReceived
from whad.hub.message import AbstractPacket
from whad.exceptions import WhadDeviceDisconnected


logger = logging.getLogger(__name__)

class Master(ANT):
    """
    ANT connector to emulate an ANT Master node.
    """

    def __init__(self, device):
        ANT.__init__(self, device)

        self.__started = False
        # Check if device can list channels
        if not self.can_list_channels():
            raise UnsupportedCapability("ListChannels")

        # Check if device can list networks
        if not self.can_list_networks():
            raise UnsupportedCapability("ListNetworks")

        # Check if device can manage channels
        if not self.can_manage_channels():
            raise UnsupportedCapability("ManageChannels")

        # Check if device can send packets
        if not self.can_send():
            raise UnsupportedCapability("Send")

        # Instantiate ANT Stack
        self.__stack = ANTStack(self)
        self._enable_role()

    def _enable_role(self):
        """Enable Master role.
        """
        if self.__started:
            self.start()


    def start(self):
        """Start Master mode.
        """
        super().start()
        self.__started = True

    def stop(self):
        """Stop Master mode.
        """
        super().stop()
        self.__started = False

    def on_pdu(self, pdu):
        """Incoming PDU handler.

        Forwards PDU to the stack if connector is started.
        """
        if self.__started:
            self.__stack.on_pdu(pdu)


    def on_channel_event(self, channel_number, event):
        """Incoming channel event handler.

        Forwards event to the stack if connector is started.
        """
        if self.__started:
            self.__stack.on_channel_event(channel_number, event)
