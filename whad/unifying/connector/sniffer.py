from whad.unifying.connector import Unifying
from whad.unifying.sniffing import SnifferConfiguration
from whad.unifying.crypto import LogitechUnifyingDecryptor
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type

from whad.scapy.layers.unifying import Logitech_Encrypted_Keystroke_Payload

class Sniffer(Unifying):
    """
    Logitech Unifying Sniffer interface for compatible WHAD device.
    """
    def __init__(self, device):
        super().__init__(device)

        self.__configuration = SnifferConfiguration()
        self.__decryptor = LogitechUnifyingDecryptor()

        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")


    def _enable_sniffing(self):
        for key in self.__configuration.keys:
            self.__decryptor.add_key(key)

        if self.__configuration.scanning:
            channel = None
        else:
            channel = self.__configuration.channel

        ack = self.__configuration.acknowledgements
        address = self.__configuration.address

        self.sniff_unifying(channel=channel, show_acknowledgements=ack, address=address)

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

            message = self.wait_for_message(filter=message_filter('unifying', message_type))
            packet = self._build_scapy_packet_from_message(message.unifying, message_type)

            if Logitech_Encrypted_Keystroke_Payload in packet and self.__configuration.decrypt:
                decrypted, success = self.__decryptor.attempt_to_decrypt(packet)
                if success:
                    packet.decrypted = decrypted

            yield packet
