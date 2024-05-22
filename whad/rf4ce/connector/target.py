from whad.rf4ce.connector import RF4CE
from whad.exceptions import UnsupportedCapability
from whad.dot15d4.stack import Dot15d4Stack
from whad.dot15d4.stack.mac import MACManager
from whad.dot15d4.address import Dot15d4Address
from whad.rf4ce.stack.nwk import NWKManager

import logging

logger = logging.getLogger(__name__)

class Target(RF4CE):
    """
    RF4CE Target Node interface for compatible WHAD device.
    """
    def __init__(self, device, profiles=[]):
        RF4CE.__init__(self, device)

        # Check if device can act as target node

        if not self.can_be_coordinator():
            raise UnsupportedCapability("Target")

        # Stack initialization
        MACManager.add(NWKManager)
        self.__stack = Dot15d4Stack(self)

        # Channel initialization
        self.__channel = 15
        self.__channel_page = 0

        self.__stack.get_layer('mac').set_extended_address(Dot15d4Address("11:22:33:44:55:66:77:88").value)
        self.__stack.get_layer('mac').set_short_address(Dot15d4Address(0x0384).value)
        self.__stack.get_layer('mac').database.set("macPanId", 0x1234)
        #self.__stack.get_layer('mac').database.set("macAckTimeout", 0.5)

        for profile in profiles:
            self.__stack.get_layer('apl').add_profile(profile)

        self.enable_reception()


    @property
    def stack(self):
        return self.__stack

    def enable_reception(self):
        self.set_coordinator_mode(channel=self.__channel)

    def set_channel(self, channel=11):
        self.__channel = channel
        self.enable_reception()

    def perform_ed_scan(self, channel):
        if not self.can_perform_ed_scan():
            raise UnsupportedCapability("EnergyDetection")
        self.__channel = channel
        super().perform_ed_scan(channel)

    def set_channel_page(self, page=0):
        if page != 0:
            raise UnsupportedCapability("ChannelPageSelection")
        else:
            self.__channel_page = page

    def auto_discovery(self):
        self.__stack.get_layer('nwk').get_service('management').auto_discovery()

    def discovery_response(self, status, destination_address):
        self.__stack.get_layer('nwk').get_service('management').discovery_response(
            status,
            Dot15d4Address(destination_address).value
        )



    def get_channel(self):
        return self.__channel

    def get_channel_page(self):
        return self.__channel_page


    def send(self, packet):
        packet.reserved = 1
        packet.do_build()
        super().send(packet, channel=self.__channel)

    def on_pdu(self, pdu):
        if (
            hasattr(pdu,"metadata") and
            hasattr(pdu.metadata, "is_fcs_valid") and
            not pdu.metadata.is_fcs_valid
        ):
            return

        self.__stack.on_pdu(pdu)

    def on_ed_sample(self, timestamp, sample):
        self.__stack.on_ed_sample(timestamp, sample)
