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
from whad.ant.stack.llm.exceptions import NoAvailableChannels, NoAvailableNetworks, \
    InvalidChannel
from whad.ant.channel import ChannelDirection
from queue import Queue
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

        self.__transfer_events = Queue()
        self.__opened = False

    def mark_as_opened(self):
        """Mark the channel as opened.
        """
        self.__opened = True

    def is_opened(self):
        """Indicates if the channel is open or not.
        """
        return self.__opened

    def add_transfer_event(self, event):
        """Add a transfer channel event to the related queue.
        """
        self.__transfer_events.put(event)

    def get_pending_transfer_event(self):
        """Return the next pending transfer channel event.
        """
        return self.__transfer_events.get()

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


    def search_channel(
        self,
        device_number,
        device_type,
        transmission_type,
        channel_period = 32768,
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
        
        self.get_layer('phy').set_network_key(network_number, network_key)
        self.get_layer('phy').set_device_number(channel_number, device_number)
        self.get_layer('phy').set_device_type(channel_number, device_type)
        self.get_layer('phy').set_transmission_type(channel_number, transmission_type)
        
        self.get_layer('phy').assign_channel(
            channel_number,
            network_number,
            shared=shared,
            direction=ChannelDirection.RX,
            unidirectional=unidirectional
        )
        
        self.get_layer('phy').set_rf_channel(channel_number, rf_channel)
        self.get_layer('phy').set_channel_period(channel_number, channel_period)
        self.get_layer('phy').open_channel(channel_number)
    
        # Instantiate a Applicative layer (contextual) to handle the channel
        app_instance = self.instantiate(AppLayer)
        app_instance.set_channel_number(channel_number)
        print(app_instance)

        channel = self.state.register_channel(
            app_instance,
            channel_number,
            ChannelDirection.RX,
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
        return channel

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
        
        self.get_layer('phy').set_network_key(network_number, network_key)
        self.get_layer('phy').set_device_number(channel_number, device_number)
        self.get_layer('phy').set_device_type(channel_number, device_type)
        self.get_layer('phy').set_transmission_type(channel_number, transmission_type)
        
        self.get_layer('phy').assign_channel(
            channel_number,
            network_number,
            shared=shared,
            direction=ChannelDirection.TX,
            unidirectional=unidirectional)
        
        self.get_layer('phy').set_rf_channel(channel_number, rf_channel)
        self.get_layer('phy').set_channel_period(channel_number, channel_period)
        self.get_layer('phy').open_channel(channel_number)
    
        # Instantiate a Applicative layer (contextual) to handle the channel
        app_instance = self.instantiate(AppLayer)
        app_instance.set_channel_number(channel_number)

        channel = self.state.register_channel(
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
        channel.mark_as_opened()
        return channel

    @instance('app', tag='broadcast')
    def _send_broadcast(self, app_inst: Layer, channel_number:int, payload : bytes):
        return self.broadcast(channel_number, payload)

    def broadcast(self,channel_number, payload):
        if channel_number not in self.state.channels:
            raise InvalidChannel()

        channel = self.state.channels[channel_number]
        
        payload = bytes(payload)
        if len(payload) < 8:
            payload = payload  + b"\x00" * (8 - len(payload))
        elif len(payload) > 8:
            payload = payload[:8]
        
        packet = (
            ANT_Hdr(
                device_number = channel.device_number, 
                device_type = channel.device_type, 
                transmission_type = channel.transmission_type, 
                broadcast = 0,
                ack = 0, 
                end = 0,
                count = 0, 
                slot = True, 
                unknown = 2

            ) / payload
        )
        
        return self.send('phy',
            packet, 
            channel_number = channel_number
        )


    @instance('app', tag='ack')
    def _send_ack(self,l2cap_inst: Layer, channel_number:int, payload : bytes):
        return self.ack(channel_number, payload)

    def ack(self, channel_number, payload):
        if channel_number not in self.state.channels:
            raise InvalidChannel()


        payload = bytes(payload)
        if len(payload) < 8:
            payload = payload  + b"\x00" * (8 - len(payload))
        elif len(payload) > 8:
            payload = payload[:8]

        channel = self.state.channels[channel_number]

        packet = (
            ANT_Hdr(
                device_number = channel.device_number, 
                device_type = channel.device_type, 
                transmission_type = channel.transmission_type, 
                broadcast = "ack/burst", 
                ack = 0, 
                end = 1,
                count = 0, 
                slot = 1,
                unknown = 2

            ) / payload
        )
        
        success = self.send('phy',
            packet, 
            channel_number = channel_number
        )
        event = channel.get_pending_transfer_event()
        if event == ChannelEventCode.EVENT_TRANSFER_TX_COMPLETED:
            return True
        else:
            return False



    @instance('app', tag='burst')
    def _send_burst(self, l2cap_inst: Layer, channel_number:int, payloads:tuple):
        return self.burst(channel_number, *payloads)

    def burst(self, channel_number, *payloads):
        if channel_number not in self.state.channels:
            raise InvalidChannel()

        channel = self.state.channels[channel_number]

        burst_payload = b""
        for payload in payloads:
            burst_payload += bytes(payload)
        
        packets = []
        count = 0
        for i in range(0, len(burst_payload), 8):
            packets.append(
                ANT_Hdr(
                    device_number = channel.device_number, 
                    device_type = channel.device_type, 
                    transmission_type = channel.transmission_type, 
                    broadcast = "ack/burst", 
                    ack = 0, 
                    end = 0,
                    count = count, 
                    slot = 0,
                    unknown = 2
                ) / burst_payload[i:i+8]
            )
            count = 1 - count
        
        if channel == ChannelDirection.TX:
            packets[0].slot = 1

        packets[-1].end = 1

        for packet in packets:        
            success = self.send('phy',
                packet,
                channel_number = channel_number
            )
        event = channel.get_pending_transfer_event()
        if event == ChannelEventCode.EVENT_TRANSFER_TX_COMPLETED:
            return True
        else:
            return False

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
        #logger.debug("Channel Event on channel # + " + str(channel_number) + " : " +str(event))
        if channel_number in self.state.channels:
            if event in (
                ChannelEventCode.EVENT_TRANSFER_TX_COMPLETED, 
                ChannelEventCode.EVENT_TRANSFER_TX_FAILED
            ):
                self.state.channels[channel_number].add_transfer_event(event)

    @source('phy')
    def on_pdu(self, pdu: ANT_Hdr, channel_number : int):
        """Packet reception callback.

        This callback dispatches the received packets to
        correct callbacks depending on the current mode.
        """
        if channel_number in self.state.channels:
            if not self.state.channels[channel_number].is_opened():
                self.state.channels[channel_number].mark_as_opened()

            app_instance = self.state.channels[channel_number].app
            self.send(app_instance.name, pdu)


LinkLayer.add(AppLayer)
