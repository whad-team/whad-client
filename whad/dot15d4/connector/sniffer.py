from whad.dot15d4.connector import Dot15d4
from whad.zigbee.sniffing import SnifferConfiguration
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type
from whad.common.sniffing import EventsManager
from whad.hub.dot15d4 import RawPduReceived, PduReceived


class Sniffer(Dot15d4, EventsManager):
    """
    802.15.4 Sniffer interface for compatible WHAD device.
    """
    def __init__(self, device):
        Dot15d4.__init__(self, device)
        EventsManager.__init__(self)

        self.__configuration = SnifferConfiguration()

        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _enable_sniffing(self):
        self.sniff_dot15d4(channel=self.__configuration.channel)

    @property
    def configuration(self):
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    @property
    def channel(self):
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel=11):
        self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()


    def available_actions(self, filter=None):
        actions = []
        return [action for action in actions if filter is None or isinstance(action, filter)]

    def sniff(self):
        while True:
            if self.support_raw_pdu():
                message_type = RawPduReceived
            else:
                message_type = PduReceived

            message = self.wait_for_message(filter=message_filter(message_type))
            packet = self.translator.from_message(message)
            self.monitor_packet_rx(packet)
            yield packet
