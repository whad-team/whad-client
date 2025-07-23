"""
Pythonic ANT stack
"""
import logging
from typing import Optional

from whad.ant.stack.llm import LinkLayer
from whad.common.stack import Layer, alias, source
from whad.hub.ant import ChannelEventCode

logger = logging.getLogger(__name__)

@alias('phy')
class ANTStack(Layer):
    """
    This class holds the main components of a (hackable) ANT stack:

    - the Link Layer (LL)
    - the Applicative Layer (APP)

    The Link Layer handles all the low-level operations, e.g., packet
    transmission, reception, synchronization and acknowledgements.
    Generally, a specific Applicative layer is implemented on the top of
    this stack (e.g., ANT+, ANT-FS).
    """

    def __init__(self, connector, options: Optional[dict] = None):
        """
        Create an instance of ANT associated with a specific connector. This
        connector provides the transport layer.

        :param connector: Connector to use with this stack.
        :type connector: WhadDeviceConnector
        :param options: Options for this layer
        :type options: dict, optional
        """

        # Initialize with provided options or empty dict if options is None.
        super().__init__(options=options or {})

        # Save connector (used as PHY layer)
        self.__connector = connector

    @property
    def ll(self):
        """Return the associated link-layer instance

        :return: Link-layer instance
        :rtype: Layer
        """
        return self.get_layer('ll')


    @property
    def app(self):
        """Return the assiociated application layer

        :return: Application layer instance
        :rtype: Layer
        """
        return self.get_layer('app')

    def on_pdu(self, pdu):
        '''PDU callback.

        This callback handles a received PDU.
        '''
        logger.debug('received a PDU (%d bytes).', len(pdu))
        self.send('ll', pdu)

    def on_channel_event(self, channel_number : int, event : ChannelEventCode):
        '''Channel Event callback.

        This callback handles an incoming channel event.
        '''
        logger.debug('received a channel event for channel #%d: %d.', channel_number, str(event))
        self.get_layer('ll').on_channel_event(channel_number, event)

    @source('ll')
    def send_pdu(self,  packet: bytes, channel_number: int = 0, rf_channel: Optional[int] = None):
        """Send an ANT PDU

        :param packet: PDU to send
        :type packet: Packet
        :param channel_number: channel number to use for transmission
        :type channel_number: int
        :param rf_channel: RF channel to use for transmission
        :type rf_channel: int, optional
        """
        logger.debug('transmitted a PDU (%d bytes).', len(packet))

        return self.__connector.send(
                                        pdu,
                                        channel_number=channel_number,
                                        rf_channel=rf_channel,
                                        add_crc = True
        )

ANTStack.add(LinkLayer)
