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
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY, ANT_FS_NETWORK_KEY
from whad.scapy.layers.ant import ANT_Hdr
from whad.ant.channel import ChannelDirection
from whad.hub.ant import ChannelEventCode
from whad.common.stack import Layer, alias, source, state, LayerState, instance
from whad.ant.stack.llm.exceptions import NoAvailableChannels, NoAvailableNetworks
from whad.ant.channel import ChannelDirection

from whad.ant.stack.app import AppLayer


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
    def app(self) -> AppLayer:
        """Applicative layer instance.
        """
        return self.__app

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
        self.channels = {}
        self.networks = {}


    def register_channel(
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
        """Register a new channel.
        """

        self.channels[channel_number] = ANTChannel(
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
        )
        return self.channels[channel_number]

    def unregister_channel(self, channel_number):
        """Unregister a channel.
        """
        if channel_number in self.channels:
            del self.channels[channel_number]

    def register_network(self, network_key) -> int:
        """Register a new network or return an existing one according to provided key.
        """
        if network_key not in self.networks.values():
            new_network_number = len(self.networks.values())
            self.networks[new_network_number] = network_key
            return new_network_number

        for network_number, candidate_key in self.networks.items():
            if network_key == candidate_key:
                return network_number


    def unregister_network(self, network) -> bool:
        """Unregister an existing network according to a network number or a network key.
        """
        if isinstance(network, int):
            if network in self.networks:
                del self.networks[network]
                return True
            return False

        else:
            for network_number, candidate_key in self.networks.items():
                if candidate_key == network:
                    del self.networks[network_number]
                    return True
            return False


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

    def _next_available_channel_number(self):
        """Returns the next available channel number.
        """
        candidates = list(range(self.get_layer('phy').max_channels))
        for already_used in self.state.channels:
            candidates.remove(already_used)
        if len(candidates) > 0:
            return min(candidates)
        else:
            return None

    # def search_channel(self, dev_number, dev_type, transmission_type):
        # ...

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
        channel_number = self._next_available_channel_number()
        if channel_number is None:
            raise NoAvailableChannels()
        
        network_number = self.state.register_network(network_key)
        if network_number >= self.get_layer('phy').max_networks:
            raise NoAvailableNetworks()

        if ( 
            self.get_layer('phy').set_network_key(network_number, network_key) and 
            self.get_layer('phy').set_device_number(channel_number, device_number) and 
            self.get_layer('phy').set_device_type(channel_number, device_type) and 
            self.get_layer('phy').set_transmission_type(channel_number, transmission_type) and 
            
            self.get_layer('phy').assign_channel(
                channel_number,
                network_number,
                shared=shared,
                direction=ChannelDirection.TX,
                unidirectional=unidirectional)  and 
            
            self.get_layer('phy').set_rf_channel(channel_number, rf_channel) and 
            self.get_layer('phy').set_channel_period(channel_number, channel_period) and 
            self.get_layer('phy').open_channel(channel_number)
        ):

            # Instantiate a Applicative layer (contextual) to handle the channel
            app_instance = self.instantiate(AppLayer)
            app_instance.set_channel_number(channel_number)
            print(app_instance)

            return self.state.register_channel(
                app_instance,
                channel_number,
                ChannelDirection.TX,
                rf_channel,
                device_number,
                device_type,
                transmission_type,
                channel_period,
                network_key,
                unidirectional,
                shared,
                background
            )
            

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
    def on_pdu(self, pdu: ANT_Hdr, channel_number : int):
        """Packet reception callback.

        This callback dispatches the received packets to
        correct callbacks depending on the current mode.
        """
        if channel_number in self.state.channels:
            app_instance = self.state.channels[channel_number].app
            print(app_instance.name)
            self.send(app_instance.name, pdu)


LinkLayer.add(AppLayer)
