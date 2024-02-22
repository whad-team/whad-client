from whad.zigbee.connector import Zigbee
from whad.dot15d4.stack import Dot15d4Stack
from whad.dot15d4.stack.mac import MACManager
from whad.zigbee.stack.nwk import NWKManager
from whad.exceptions import UnsupportedCapability

class Coordinator(Zigbee):
    """
    Zigbee End Device interface for compatible WHAD device.
    """
    def __init__(self, device, applications=[]):
        super().__init__(device)

        if not self.can_be_coordinator():
            raise UnsupportedCapability("Coordinator")

        # Stack initialization
        MACManager.add(NWKManager)
        self.__stack = Dot15d4Stack(self)

        # Channel initialization
        self.__channel = 11
        self.__channel_page = 0

        self.enable_reception()

        #self.__stack.get_layer('apl').initialize()
        #self._init_applications(applications)

    def network_formation(self, pan_id=None, channel=None):
        return self.__stack.get_layer('nwk').get_service("management").network_formation(
            pan_id = pan_id,
            channel = channel
        )

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
