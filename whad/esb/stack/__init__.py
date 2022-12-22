from whad.esb.stack.llm import EsbLinkLayerManager

"""
Pythonic Enhanced ShockBurst stack
"""
class ESBStack:
    """
    This class holds the main components of a (hackable) Enhanced ShockBurst stack:

    - the Link Layer (LL)
    - the Applicative Layer (APP)

    The Link Layer handles all the low-level operations, e.g., packet transmission, reception, synchronization and acknowledgements.
    Generally, a proprietary Applicative layer is implemented on the top of this stack (e.g., Unifying, Microsoft).

    """
    def __init__(self, connector, app_class=None):
        """
        Create an instance of Enhanced ShockBurst associated with a specific connector. This
        connector provides the transport layer.

        :param WhadDeviceConnector connector: Connector to use with this stack.
        """
        self.__connector = connector

        # Instanciate all the required controllers
        self.__llm = EsbLinkLayerManager(self, app_class)

    @property
    def ll(self):
        return self.__llm

    @property
    def app(self):
        return self.__llm.app
    #############################
    # Incoming messages
    #############################
    def on_pdu(self, pdu):
        self.__llm.on_pdu(pdu)

    ############################
    # Interact
    ############################

    def set_channel(self, channel):
        self.__connector.channel = channel

    def get_channel(self):
        return self.__connector.channel

    def get_address(self):
        return self.__connector.address

    def set_address(self, address):
        self.__connector.address = address

    def send(self, packet, channel=None):
        if channel is None:
            channel = self.__connector.channel
        self.__connector.send(packet, channel=channel)