import logging
from typing import Generator
from time import time, sleep

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

class Slave(ANT):
    """
    ANT connector to emulate an ANT Slave node.
    """

    def __init__(self, device, profile=None):
        ANT.__init__(self, device)

        self.__profile = profile
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

    def search_channel(
        self,
        device_number=0,
        device_type=None,
        transmission_type=None,
        channel_period = None,
        rf_channel = None,
        network_key = None,
        unidirectional = False,
        shared = False,
        background = False
    ):

        if device_type is None:
            device_type = (
                self.__profile.DEVICE_TYPE if 
                self.__profile is not None else
                0
            )
        
        if transmission_type is None:
            transmission_type = (
                self.__profile.TRANSMISSION_TYPE if
                self.__profile is not None else
                0
            )

        if channel_period is None:
            channel_period = (
                self.__profile.CHANNEL_PERIOD if
                self.__profile is not None else
                32768
            )
        if rf_channel is None:
            rf_channel = (
                self.__profile.DEFAULT_RF_CHANNEL if
                self.__profile is not None else
                57
            )
        if network_key is None:
            network_key = (
                self.__profile.NETWORK_KEY if
                self.__profile is not None else
                ANT_PLUS_NETWORK_KEY
            )
        channel = self.stack.get_layer('ll').search_channel(
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

            while not channel.is_opened():
                sleep(0.1)

            if self.__profile is not None:
                channel.app.set_profile(self.__profile)
        return channel 
               

    def start(self):
        """Start Slave  mode.
        """
        self.__started = True

    def stop(self):
        """Stop Slave mode.
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
