from whad.zigbee.connector import Zigbee
from whad.zigbee.stack import ZigbeeStack
from whad.exceptions import UnsupportedCapability
from whad.zigbee.profile.network import Network
from whad.zigbee.stack.apl.application import ApplicationObject

class EndDevice(Zigbee):
    """
    Zigbee End Device interface for compatible WHAD device.
    """
    def __init__(self, device, applications=[]):
        super().__init__(device)

        if not self.can_be_end_device():
            raise UnsupportedCapability("EndDevice")

        self.__stack = ZigbeeStack(self)
        self.__channel = 11
        self.__channel_page = 0
        self.__network = None
        self.enable_reception()

        self.__stack.apl.initialize()
        self._init_applications(applications)

    def _init_applications(self, applications):
        if applications == []:
            # If no application provided, attach a default ZCL application on endpoint 1
            app = ApplicationObject("zcl_app", 0x0104, 0x0100, device_version=0, input_clusters=[], output_clusters=[])
            self.stack.apl.attach_application(app, endpoint=1)

        else:
            for app in applications:
                endpoint = 1
                self.stack.apl.attach_application(app, endpoint=endpoint)
                endpoint += 1


    def discover_networks(self):
        return self.__stack.apl.get_application_by_name("zdo").network_manager.discover_networks()

    def join(self, network=None):
        if isinstance(network, int):
            for candidate_network in self.discover_networks():
                if candidate_network.extended_pan_id == network or candidate_network.pan_id == network:
                    if candidate_network.join():
                        self.__network = candidate_network
                        return self.__network
            return None
        elif isinstance(network, Network):
            if network.join():
                self.__network = candidate_network
                return self.__network
            return None
        return None

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
