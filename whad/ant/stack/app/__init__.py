"""
ANT Stack Application manager
"""
import logging
from whad.common.stack import Layer, alias, source, state, LayerState, ContextualLayer
from whad.scapy.layers.ant import ANT_Hdr

logger = logging.getLogger(__name__)

@alias('app')
class AppLayer(ContextualLayer):
    """ANT Application layer implementation
    """

    def configure(self, options=None):
        """Layer configuration
        """
        # Initialize state
        self.state.channel_number = None
        self.state.profile = None

    def set_profile(self, profile):
        '''Configure the profile.
        '''
        self.state.profile = profile
        self.state.profile.set_application(self)

    def search_compatible_channel(
            self,
            device_number = 0,
            device_type = None,
            transmission_type = None,
            channel_period = None, 
            rf_channel = None, 
            network_key = None,
            unidirectional = False,
            shared = False,
            background = False
        ):
        if self.state.profile is None:
            return None

        if device_type is None:
            device_type = self.state.profile.DEVICE_TYPE
        
        if transmission_type is None:
            transmission_type = self.state.profile.TRANSMISSION_TYPE

        if channel_period is None:
            channel_period = self.state.profile.CHANNEL_PERIOD

        if rf_channel is None:
            rf_channel = self.state.profile.DEFAULT_RF_CHANNEL

        if network_key is None:
            rf_channel = self.state.profile.NETWORK_KEY

        return self.get_layer('ll').search_channel(
            device_number,
            device_type,
            transmission_type,
            channel_period, 
            rf_channel, 
            network_key,
            unidirectional,
            shared,
            background
        )

    def broadcast(self, payload):
        '''Transmit a PDU in broadcast.
        '''
        return self.send('ll', self.state.channel_number, payload=payload, tag='broadcast')

    def ack(self, payload):
        '''Transmit a PDU in ack mode.
        '''
        return self.send('ll', self.state.channel_number, payload=payload, tag='ack')

    def burst(self, *payloads):
        '''Transmit a PDU in burst mode.
        '''
        return self.send('ll', self.state.channel_number, payloads=payloads, tag='burst')

    def set_channel_number(self, channel_number: int):
        '''Save current channel number
        '''
        self.state.channel_number = channel_number

    def get_channel_number(self) -> int:
        """Retrieve current channel number
        """
        return self.state.channel_number

    @source('ll')
    def on_pdu(self, pdu):
        """Handles incoming data"""
        if ANT_Hdr in pdu and pdu.broadcast == 0:
            self.on_broadcast(pdu[1:])
        else:
            self.on_ack_burst(pdu[1:])

    def on_broadcast(self, payload):
        logger.debug("Incoming Broadcast payload:" +  repr(payload))
        if self.state.profile is not None:
            self.state.profile.on_broadcast(payload)

    def on_ack_burst(self, payload):
        logger.debug("Incoming Ack/Burst payload:" +  repr(payload))
        if self.state.profile is not None:
            self.state.profile.on_ack_burst(payload)