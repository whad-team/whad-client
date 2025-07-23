"""
WHAD ANT Stack - Link-layer management

This module provides the ANT stack Link-layer management class
`LinkLayer`. This class uses its own associated state class
`LinkLayerState`.
"""
import logging
from queue import Queue, Empty
from time import sleep, time
from typing import Optional, Generator

from scapy.packet import Packet

from whad.scapy.layers.ant import ANT_Hdr
from whad.ant.channel import ChannelDirection
from whad.hub.ant import ChannelEventCode
from whad.common.stack import Layer, alias, source, state, LayerState, instance

logger = logging.getLogger(__name__)


class ANTChannel:
    """ANT Channel implementation
    """

    def __init__(
            self,
            app_instance,
            channel_number,
            direction,
            rf_channel,
            device_number,
            device_type,
            transmission_type,
            channel_period,
            network_key,
            unidirectional,
            shared,
            background
    ):
        self.__app = app_instance
        self.__channel_number = channel_number
        self.__direction = direction
        self.__rf_channel = rf_channel
        self.__device_number = device_number
        self.__device_type = device_type
        self.__transmission_type = transmission_type
        self.__channel_period = channel_period
        self.__network_key = network_key
        self.__unidirectional = unidirectional
        self.__shared = shared
        self.__background = background



    @property
    def channel_number(self) -> int:
        """Channel number
        """
        return self.__channel_number

    @property
    def direction(self) -> ChannelDirection:
        """Channel direction
        """
        return self.__direction

    @property
    def rf_channel(self) -> int:
        """RF Channel in use
        """
        return self.__rf_channel


    @property
    def network_key(self) -> int:
        """Assigned network key
        """
        return self.__network_key

    @property
    def device_number(self) -> int:
        """Assigned device number
        """
        return self.__device_number


    @property
    def device_type(self) -> int:
        """Assigned device type
        """
        return self.__device_type

    @property
    def transmission_type(self) -> int:
        """Assigned transmission type
        """
        return self.__transmission_type

    @property
    def channel_period(self) -> int:
        """Assigned channel period
        """
        return self.__channel_period


    @property
    def unidirectional(self) -> bool:
        """Flag indicating if the channel is unidirectional or bidirectional
        """
        return self.__unidirectional

    @property
    def shared(self) -> bool:
        """Flag indicating if the channel is shared or not
        """
        return self.__shared


    @property
    def background(self) -> bool:
        """Flag indicating if the channel is in background mode or not
        """
        return self.__background

class LinkLayerState(LayerState):
    """ANT Link-layer state class.

    This class stores the link-layer state.
    """

    def __init__(self):
        """Initialization of link-layer state.
        """
        super().__init__()


@alias('ll')
@state(LinkLayerState)
class LinkLayer(Layer):
    """ANT Link-layer management class.

    This class manages a single ANT connection and its state,
    as well as promiscuous mode.
    """

    def configure(self, options: Optional[dict] = None):
        """Configure this ANT link-layer instance.

        This method is called by the underlying layer management
        system to configure this layer.

        :param options: Layer options
        :type options: dict, optional
        """
        pass

    @property
    def app(self):
        """Return the associated application layer instance

        :return: Associated application layer instance
        :rtype: Layer
        """
        return self.get_layer('app')


    @source('phy')
    def on_channel_event(self, channel_number : int, event : ChannelEventCode):
        """Channel event callback.

        This callback dispatches the received events to
        correct callbacks depending on the current mode.
        """
        print("[event] #%d, %s" % (channel_number, str(event)))

    @source('phy')
    def on_pdu(self, pdu: ANT_Hdr):
        """Packet reception callback.

        This callback dispatches the received packets to
        correct callbacks depending on the current mode.
        """
        print(repr(pdu))