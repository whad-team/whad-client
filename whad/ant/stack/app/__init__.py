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
        print("[APP]", repr(pdu))
        if ANT_Hdr in pdu and pdu.broadcast == 0:
            self.on_broadcast(pdu[1:])
        else:
            self.on_ack_burst(pdu[1:])

    def on_broadcast(self, payload):
        print("[APP] broadcast payload:", payload)
        if self.state.profile is not None:
            self.state.profile.on_broadcast(payload)

    def on_ack_burst(self, payload):
        print("[APP] ack/burst payload:", payload)
        if self.state.profile is not None:
            self.state.profile.on_ack_burst(payload)