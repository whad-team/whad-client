"""
Pythonic 802.15.4 stack
"""

from whad.protocol.dot15d4.dot15d4_pb2 import AddressType
from whad.dot15d4.utils.phy import PHYS
from whad.dot15d4.stack.mac import MACManager

from whad.common.stack import Layer, alias, source

import logging
logger = logging.getLogger(__name__)

@alias('phy')
class Dot15d4Stack(Layer):
    """
    This class holds the main components of a (hackable) 802.15.4 stack:

    - the Medium Access Control Manager (MAC - defined in 802.15.4 specification)

    The Medium Access Control manager handles all the low-level operations:
    - 802.15.4 management control (handles beaconing, frame validation, timeslots and associations)
    - 802.15.4 data (forward to upper layer, i.e. NWK)
    """

    def __init__(self, connector, phy=PHYS["802.15.4-OQPSK"], options={}):
        super().__init__(options=options)

        # Save connector (used as PHY layer)
        self.__connector = connector

        # Save selected physical layer
        self.__selected_phy = phy


    @property
    def symbol_duration(self):
        """
        Compute symbol duration (in us).
        """
        return (4 / self.__selected_phy.datarate)

    #############################
    # Incoming messages
    #############################
    def on_pdu(self, pdu):
        '''PDU callback.

        This callback handles a PDU and forwards it to MAC layer.
        '''
        logger.debug('received a PDU (%d bytes)' % (len(pdu)))
        self.send('mac', pdu, tag='pdu')

    def on_ed_sample(self, timestamp, sample):
        '''Energy Detection sample callback.

        This callback handle an Energy Detection sample and forwards it to MAC layer.
        '''
        logger.debug('received an energy detection sample (%d / timestamp=%d) ' % (sample, timestamp))

        # Notify link layer we received a control PDU for a given `conn_handle`.
        self.send('mac', sample, tag='energy_detection', timestamp=timestamp)

    ############################
    # Interact
    ############################

    def set_short_address(self, address):
        '''Select short address.
        '''
        self.__connector.set_node_address(address, mode=AddressType.SHORT)

    def set_extended_address(self, address):
        '''Select extended address.
        '''
        self.__connector.set_node_address(address, mode=AddressType.EXTENDED)

    def set_channel(self, channel):
        '''Select channel.
        '''
        self.__connector.set_channel(channel)

    def set_channel_page(self, page):
        '''Select channel page.
        '''
        self.__connector.set_channel_page(page)

    def get_channel(self):
        '''Get channel.
        '''
        return self.__connector.get_channel()

    def get_channel_page(self):
        '''Get channel page.
        '''
        return self.__connector.get_channel_page()

    def perform_ed_scan(self, channel):
        '''Start an Energy Detection scan.
        '''
        self.__connector.perform_ed_scan(channel)

    @source('mac', 'pdu')
    def transmit(self, packet):
        '''Send PDU to the underlying WHAD connector.
        '''
        self.__connector.send(packet)

Dot15d4Stack.add(MACManager)
