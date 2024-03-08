from whad.rf4ce.connector import RF4CE
from whad.rf4ce.sniffing import SnifferConfiguration
from whad.rf4ce.crypto import RF4CEDecryptor, RF4CEKeyDerivation
from whad.rf4ce.utils.adpcm import ADPCM
from whad.rf4ce.exceptions import MissingCryptographicMaterial
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type
from whad.rf4ce.sniffing import KeyExtractedEvent
from whad.common.sniffing import EventsManager
import logging

logger = logging.getLogger(__name__)

class Sniffer(RF4CE, EventsManager):
    """
    RF4CE Sniffer interface for compatible WHAD device.
    """
    def __init__(self, device):
        RF4CE.__init__(self, device)
        EventsManager.__init__(self)


        self.__configuration = SnifferConfiguration()
        self.__decryptor = RF4CEDecryptor()
        self.__key_derivation = RF4CEKeyDerivation()
        self.__audio_stream = ADPCM()

        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _enable_sniffing(self):
        for key in self.__configuration.keys:
            self.__decryptor.add_key(key)
        for address in self.__configuration.addresses:
            self.__decryptor.add_address(address)
        self.sniff_rf4ce(channel=self.__configuration.channel)

    def add_key(self, key):
        self.__configuration.keys.append(key)

    def clear_keys(self):
        self.__configuration.keys = []

    def add_address(self, key):
        self.__configuration.addresses.append(address)

    def clear_addresses(self):
        self.__configuration.addresses = []

    @property
    def decrypt(self):
        return self.__configuration.decrypt

    @decrypt.setter
    def decrypt(self, decrypt):
        self.__configuration.decrypt = decrypt


    @property
    def channel(self):
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel=15):
        self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()


    @property
    def configuration(self):
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    def sniff(self):
        while True:
            if self.support_raw_pdu():
                message_type = "raw_pdu"
            else:
                message_type = "pdu"

            message = self.wait_for_message(filter=message_filter('dot15d4', message_type))
            packet = self.translator.from_message(message.dot15d4, message_type)
            self.monitor_packet_rx(packet)


            if self.__configuration.pairing:
                self.__key_derivation.process_packet(packet)
                if self.__key_derivation.key is not None:
                    logger.info("[i] New key extracted: ", self.__key_derivation.key.hex())
                    self.trigger_event(KeyExtractedEvent(self.__key_derivation.key))
                    self.__decryptor.add_key(self.__key_derivation.key)
                    self.__key_derivation.reset()

            if (
                hasattr(packet, "fcf_destaddrmode") and
                packet.fcf_destaddrmode == 3
            ):
                self.__decryptor.add_address(packet.dest_addr)

            if (
                hasattr(packet, "fcf_srcaddrmode") and
                packet.fcf_srcaddrmode == 3
            ):
                self.__decryptor.add_address(packet.src_addr)

            if (
                hasattr(packet, "security_enabled") and
                packet.security_enabled == 1 and
                self.__configuration.decrypt
            ):
                try:
                    decrypted, success = self.__decryptor.attempt_to_decrypt(packet)
                    if success:
                        packet.decrypted = decrypted
                        if self.__configuration.audio:
                            self.__audio_stream.process_packet(packet.decrypted)

                except MissingCryptographicMaterial:
                    pass
            yield packet
