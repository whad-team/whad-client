from .mac import MACManager
from .nwk import NWKManager
from .constants import Dot15d4Phy
from whad.protocol.zigbee.zigbee_pb2 import AddressType
from whad.exceptions import RequiredImplementation
from scapy.config import conf
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

        conf.dot15d4_protocol = "zigbee"
        # Instanciate all the required controllers
        self.__mac = MACManager(self)
        self.__nwk = NWKManager(self.__mac)
        self.__mac.upper_layer = self.__nwk

    @property
    def phy(self):
        return self.__selected_phy

    @phy.setter
    def phy(self, new_phy):
        if new_phy != Dot15d4Phy.OQPSK:
            raise RequiredImplementation("PhySelection")
        self.__selected_phy = new_phy

    @property
    def mac(self):
        return self.__mac

    @property
    def nwk(self):
        return self.__nwk

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

    def set_short_address(self, address):
        self.__connector.set_node_address(address, mode=AddressType.SHORT)

    def set_extended_address(self, address):
        self.__connector.set_node_address(address, mode=AddressType.EXTENDED)

    def set_channel(self, channel):
        self.__connector.set_channel(channel)

    def set_channel_page(self, page):
        self.__connector.set_channel_page(page)

    def perform_ed_scan(self, channel):
        self.__connector.perform_ed_scan(channel)

    def send(self, packet):
        self.__connector.send(packet)
