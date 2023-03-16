from scapy.layers.zigbee import ZigbeeSecurityHeader
from whad.zigbee.connector import Zigbee
from whad.zigbee.sniffing import SnifferConfiguration
from whad.zigbee.crypto import ZigbeeDecryptor
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type
from whad.common.sniffing import EventsManager

class Sniffer(Zigbee, EventsManager):
    """
    Zigbee Sniffer interface for compatible WHAD device.
    """
    def __init__(self, device):
        Zigbee.__init__(self, device)
        EventsManager.__init__(self)


        self.__configuration = SnifferConfiguration()
        self.__decryptor = ZigbeeDecryptor()

        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _enable_sniffing(self):
        for key in self.__configuration.keys:
            self.__decryptor.add_key(key)
        self.sniff_zigbee(channel=self.__configuration.channel)

    def add_key(self, key):
        self.__configuration.keys.append(key)

    def clear_keys(self):
        self.__configuration.keys = []

    @property
    def decrypt(self):
        return self.__configuration.decrypt

    @decrypt.setter
    def decrypt(self, decrypt):
        self.__configuration.decrypt = decrypt

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
                message_type = "raw_pdu"
            else:
                message_type = "pdu"

            message = self.wait_for_message(filter=message_filter('zigbee', message_type))
            packet = self.translator.from_message(message.zigbee, message_type)
            self.monitor_packet_rx(packet)

            if ZigbeeSecurityHeader in packet and self.__configuration.decrypt:
                decrypted, success = self.__decryptor.attempt_to_decrypt(packet)
                if success:
                    packet.decrypted = decrypted
            yield packet
