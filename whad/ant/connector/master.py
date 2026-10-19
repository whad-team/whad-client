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
from whad.ant.stack.llm import AntChannel
from whad.ant.stack.app.profiles import AntProfile

logger = logging.getLogger(__name__)

class Master(ANT):
    """
    ANT connector to emulate an ANT Master node.
    """

    def __init__(self, device, profile:AntProfile=None):
        """Constructor of the ANT Master connector.

        :param profile: Pre-select a profile.
        :type profile: `whad.ant.stack.app.profiles.AntProfile`
        """
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
        """
        ANT Stack.
        """
        return self.__stack

    @property
    def profile(self):
        """
        ANT Profile (None if no profile selected).
        """
        return self.__profile


    def _enable_role(self):
        """Enable Master role.
        """
        if self.__started:
            super().start()


    def create_channel(
        self,
        device_number:int = None,
        device_type:int = None,
        transmission_type:int = None,
        channel_period:int = None,
        rf_channel:int = None,
        network_key:bytes = None,
        unidirectional:bool = False,
        shared:bool = False,
        background:bool = False
    ) -> AntChannel:
        """Create a new channel (and automatically starts the connector).
        
        :param device_number: Identifier of the device
        :type device_number: int
        :param device_type: Type of the device
        :type device_type: int
        :param transmission_type: Transmission type of the device
        :type transmission_type: int
        :param channel_period: Duration of a channel timeslot
        :type channel_period: int
        :param rf_channel: RF channel to use
        :type rf_channel: int
        :param network_key: Network key used by the channel
        :type network_key: bytes
        :param unidirectional: Boolean indicating if the channel is unidirectional
        :type unidirectional: bool
        :param shared: Boolean indicating if the channel is shared
        :type shared: bool
        :param background: Boolean indicating if the channel runs in background
        :type background: bool
        :return: ANT Channel if successfully created, None otherwise
        :rtype: :class:`whad.ant.stack.llm.AntChannel`
        """

        if (
            device_number is None and
            self.__profile is not None and 
            hasattr(self.__profile, "DEVICE_NUMBER")
        ):
            device_number =  self.__profile.DEVICE_NUMBER
          
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
            if self.__profile is not None:
                channel.app.set_profile(self.__profile)
                self.__profile.start()
        self.start()
        return channel 
               

    def start(self):
        """Start Master mode.
        """
        super().start()
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
