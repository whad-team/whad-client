from whad.rf4ce.connector import RF4CE
from whad.exceptions import UnsupportedCapability
from whad.dot15d4.stack import Dot15d4Stack
from whad.dot15d4.stack.mac import MACManager
from whad.dot15d4.address import Dot15d4Address
from whad.rf4ce.stack.nwk import NWKManager

import logging

logger = logging.getLogger(__name__)

class Controller(RF4CE):
    """
    RF4CE Controller Node interface for compatible WHAD device.
    """
    def __init__(self, device, profiles=[]):
        RF4CE.__init__(self, device)

        # Check if device can act as target node

        if not self.can_be_end_device():
            raise UnsupportedCapability("Controller")

        # Stack initialization
        MACManager.add(NWKManager)
        self.__stack = Dot15d4Stack(self)

        self.__stack.set_short_address(0x1234)
        self.__stack.get_layer('mac').database.set('macShortAddress', 0x1234)
        self.__stack.get_layer('nwk').database.set("nwkcNodeCapabilities",
            (1 << 3) | # channel_normalization_capable
            (1 << 2) | # security_capable
            (0 << 1) | # power_source
            (0) # node_type
            #self.__stack.get_layer('nwk').database.get("nwkcNodeCapabilities") & 0xFE
        )

        # Channel initialization
        self.__channel = 15
        self.__channel_page = 0

        for profile in profiles:
            self.__stack.get_layer('apl').add_profile(profile)
            
        self.enable_reception()


    @property
    def stack(self):
        return self.__stack

    def enable_reception(self):
        self.set_end_device_mode(channel=self.__channel)

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


    def discovery(self):
        return self.__stack.get_layer('nwk').get_service('management').discovery()


    def get_channel(self):
        return self.__channel

    def get_channel_page(self):
        return self.__channel_page


    def send(self, packet):
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
