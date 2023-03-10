from whad.unifying.connector import Unifying
from whad.unifying.sniffing import SnifferConfiguration, KeyExtractedEvent
from whad.unifying.crypto import LogitechUnifyingDecryptor, LogitechUnifyingKeyDerivation
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type
from whad.common.sniffing import EventsManager
from whad.scapy.layers.unifying import Logitech_Encrypted_Keystroke_Payload
import logging

logger = logging.getLogger(__name__)

class Sniffer(Unifying, EventsManager):
    """
    Logitech Unifying Sniffer interface for compatible WHAD device.
    """
    def __init__(self, device):
        Unifying.__init__(self, device)
        EventsManager.__init__(self)

        self.__configuration = SnifferConfiguration()
        self.__decryptor = LogitechUnifyingDecryptor()
        self.__key_derivation = LogitechUnifyingKeyDerivation()

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

        if self.__configuration.pairing:
            self.sniff_pairing()
        else:
            super().sniff(channel=channel, show_acknowledgements=ack, address=address)

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

    def add_key(self, key):
        self.stop()
        self.__configuration.keys.append(key)
        self._enable_sniffing()

    def clear_keys(self):
        self.stop()
        self.__configuration.keys = []
        self._enable_sniffing()

    @property
    def decrypt(self):
        return self.__configuration.decrypt

    @decrypt.setter
    def decrypt(self, decrypt):
        self.stop()
        self.__configuration.decrypt = decrypt
        self._enable_sniffing()

    @property
    def address(self):
        return self.__configuration.address

    @address.setter
    def address(self, address):
        self.stop()
        self.__configuration.address = address
        self._enable_sniffing()

    @property
    def scanning(self):
        return self.__configuration.scanning

    @scanning.setter
    def scanning(self, scanning):
        self.stop()
        self.__configuration.scanning = scanning
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
            packet = self.translator.from_message(message.unifying, message_type)

            if self.__configuration.pairing:
                self.__key_derivation.process_packet(packet)
                if self.__key_derivation.key is not None:
                    logger.info("[i] New key extracted: ", self.__key_derivation.key.hex())
                    self.trigger_event(KeyExtractedEvent(self.__key_derivation.key))
                    self.__key_derivation.reset()

            if Logitech_Encrypted_Keystroke_Payload in packet and self.__configuration.decrypt:
                decrypted, success = self.__decryptor.attempt_to_decrypt(packet)

                if success:
                    packet.decrypted = decrypted
            self.monitor_packet_rx(packet)
            yield packet
