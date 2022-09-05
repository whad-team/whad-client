from .mac import MACManager
from .constants import Dot15d4Phy
from whad.exceptions import RequiredImplementation

"""
Pythonic ZigBee stack
"""
class ZigbeeStack:
    """
    This class holds the main components of a (hackable) ZigBee stack:

    - the Medium Access Control Manager (MAC - defined in 802.15.4 specification)
    - the Network manager (NWK)
    - the Application manager (APS)

    The Medium Access Control manager handles all the low-level operations:
    - 802.15.4 management control (handles beaconing, frame validation, timeslots and associations)
    - 802.15.4 data (forward to upper layer, i.e. NWK)
    """
    def __init__(self, connector):
        """
        Create an instance of ZigbeeStack associated with a specific connector. This
        connector provides the transport layer.

        :param WhadDeviceConnector connector: Connector to use with this stack.
        """
        self.__connector = connector
        self.__selected_phy = Dot15d4Phy.OQPSK
        # Instanciate all the required controllers
        self.__mac = MACManager(self)

    @property
    def phy(self):
        return self.__selected_phy

    @phy.setter
    def phy(self, new_phy):
        if new_phy != Dot15d4Phy.OQPSK:
            raise RequiredImplementation("PhySelection")
        self.__selected_phy = new_phy

    @property
    def mac_services(self):
        return (self.__mac.management_service, self.__mac.data_service)

    @property
    def nwk_services(self):
        return (self.__mac.upper_layer.services)

    #############################
    # Incoming messages
    #############################
    def on_pdu(self, pdu):
        self.__mac.on_pdu(pdu)

    def on_ed_sample(self, timestamp, sample):
        self.__mac.on_ed_sample(timestamp, sample)
    ############################
    # Interact
    ############################
    def set_channel(self, channel):
        self.__connector.set_channel(channel)

    def set_channel_page(self, page):
        self.__connector.set_channel_page(page)

    def perform_ed_scan(self, channel):
        self.__connector.perform_ed_scan(channel)

    def send(self, packet):
        self.__connector.send(packet)
