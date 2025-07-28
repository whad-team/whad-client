"""
ANT Stack Application manager
"""
import logging
from whad.common.stack import Layer, alias, source, state, LayerState, ContextualLayer

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

    def set_channel_number(self, channel_number: int):
        '''Save current channel number
        '''
        self.state.channel_number = channel_number
        print("channel number = ", channel_number)

    def get_channel_number(self) -> int:
        """Retrieve current channel number
        """
        return self.state.channel_number

    @source('ll')
    def on_pdu(self, pdu):
        """Handles incoming data"""
        print("[APP]", repr(pdu))