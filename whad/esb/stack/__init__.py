"""
Pythonic Enhanced ShockBurst stack
"""
import logging
from typing import Optional

from whad.esb.stack.llm import LinkLayer
from whad.common.stack import Layer, alias, source

logger = logging.getLogger(__name__)

@alias('phy')
class ESBStack(Layer):
    """
    This class holds the main components of a (hackable) Enhanced ShockBurst stack:

    - the Link Layer (LL)
    - the Applicative Layer (APP)

    The Link Layer handles all the low-level operations, e.g., packet
    transmission, reception, synchronization and acknowledgements.
    Generally, a proprietary Applicative layer is implemented on the top of
    this stack (e.g., Unifying, Microsoft).
    """

    def __init__(self, connector, options: Optional[dict] = None):
        """
        Create an instance of Enhanced ShockBurst associated with a specific connector. This
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


    @property
    def channel(self) -> int:
        """Return current channel number

        :return: Current channel number
        :rtype: int
        """
        return self.__connector.channel

    @channel.setter
    def channel(self, channel: int):
        """Set current channel number

        :param channel: New channel number to use
        :type channel: int
        """
        self.__connector.channel = channel

    @property
    def address(self) -> str:
        """Return current ESB address

        :return: Current connector address
        :rtype: str
        """
        return self.__connector.address

    @address.setter
    def address(self, address: str):
        """Set current ESB address

        :param address: New ESB address
        :type address: str
        """
        self.__connector.address = address

    @source('ll')
    def send_pdu(self, packet, channel: Optional[int] = None,
                 retransmission_count: Optional[int] = 1):
        """Send an ESB PDU

        :param packet: PDU to send
        :type packet: Packet
        :param channel: channel to use for transmission
        :type channel: int, optional
        :param retransmission_count: Maximum number of retransmission
        :type retransmission_count: int, optional
        """
        if channel is None:
            channel = self.__connector.channel
        logger.debug('transmitted a PDU (%d bytes).', len(packet))

        return self.__connector.send(packet, channel=channel,
                                     retransmission_count=retransmission_count)

ESBStack.add(LinkLayer)
