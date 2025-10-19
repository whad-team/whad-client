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
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY

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
        self.__started = True

    @property
    def stack(self):
        return self.__stack

    def _enable_role(self):
        """Enable Master role.
        """
        if self.__started:
            super().start()

    def create_channel(
        self,
        device_number,
        device_type,
        transmission_type,
        channel_period = 32768//4,
        rf_channel = 57,
        network_key = ANT_PLUS_NETWORK_KEY,
        unidirectional = False,
        shared = False,
        background = False
    ):
        channel = self.stack.get_layer('ll').create_channel(
            device_number = device_number, 
            device_type = device_type,
            transmission_type = transmission_type,
            channel_period = channel_period,
            rf_channel = rf_channel,
            network_key = network_key,
            unidirectional = unidirectional,
            shared = shared,
            background = background           
        )
        if channel is not None:
            self._enable_role()
        return channel 
               

    def start(self):
        """Start Master mode.
        """
        self.__started = True

    def stop(self):
        """Stop Master mode.
        """
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
