"""
Pythonic ANT stack
"""
import logging
from typing import Optional

from whad.ant.stack.llm import LinkLayer
from whad.common.stack import Layer, alias, source
from whad.hub.ant import ChannelEventCode
from whad.ant.channel import ChannelDirection

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

        # Create cache variables for available channels and networks
        self.__max_channels = None
        self.__max_networks = None


    @property
    def max_channels(self):
        """Return the number of channels supported by hardware.
        """
        if self.__max_channels is None:
            self.__max_channels = self.__connector.list_channels()
        return self.__max_channels

    @property
    def max_networks(self):
        """Return the number of networks supported by hardware.
        """
        if self.__max_networks is None:
            self.__max_networks = self.__connector.list_networks()
        return self.__max_networks



    def open_channel(self, channel_number : int) -> bool:
        """
        Open an ANT channel.
        """
        return self.__connector.open_channel(channel_number = channel_number)



    def close_channel(self, channel_number : int) -> bool:
        """
        Close an ANT channel.
        """
        return self.__connector.close_channel(channel_number = channel_number)


    def set_device_number(self, channel_number : int, device_number : int) -> bool:
        """
        Configure an ANT channel with a given device number.
        """
        
        return self.__connector.set_device_number(
            channel_number = channel_number, 
            device_number = device_number
        )




    def set_transmission_type(self, channel_number : int, transmission_type : int) -> bool:
        """
        Configure an ANT channel with a given transmission type.
        """
        
        return self.__connector.set_transmission_type(
            channel_number = channel_number, 
            transmission_type = transmission_type
        )




    def set_rf_channel(self, channel_number : int, rf_channel : int) -> bool:
        """
        Configure an ANT channel with a given RF channel.
        """
        
        return self.__connector.set_rf_channel(
            channel_number = channel_number, 
            rf_channel = rf_channel
        )


    def set_network_key(self, network_number : int, network_key : bytes) -> bool:
        """
        Configure an ANT network with a given Network Key.
        """
        
        return self.__connector.set_network_key(
            network_number = network_number, 
            network_key = network_key
        )



    def set_device_type(self, channel_number : int, device_type : int) -> bool:
        """
        Configure an ANT channel with a given device type.
        """
       
        return self.__connector.set_device_type(
            channel_number = channel_number, 
            device_type = device_type
        )


    def set_channel_period(self, channel_number : int, period : int) -> bool:
        """
        Configure an ANT channel with a given channel period.
        """

        return self.__connector.set_channel_period(
            channel_number = channel_number, 
            period = period
        )

    def unassign_channel(self, channel_number : int) -> bool:
        """
        Unassign an ANT channel.
        """
        
        return self.__connector.unassign_channel(
            channel_number = channel_number
        )


    def assign_channel(
            self,
            channel_number : int, 
            network_number : int, 
            direction : ChannelDirection = ChannelDirection.RX, 
            unidirectional : bool = False, 
            shared : bool = False, 
            background_scanning : bool = True
    ) -> bool:
        """
        Assign an ANT channel.
        """
        return self.__connector.assign_channel(
            channel_number = channel_number, 
            network_number = network_number, 
            direction = direction, 
            unidirectional = unidirectional, 
            shared = shared, 
            background_scanning = background_scanning
        )

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
        self.send('ll', pdu, channel_number=pdu.metadata.channel_number)

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
print(ANTStack.export())