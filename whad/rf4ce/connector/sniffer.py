from whad.rf4ce.connector import RF4CE
from whad.rf4ce.sniffing import SnifferConfiguration
from whad.rf4ce.crypto import RF4CEDecryptor, RF4CEKeyDerivation
from whad.rf4ce.utils.adpcm import ADPCM
from whad.rf4ce.exceptions import MissingCryptographicMaterial
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type
from whad.rf4ce.sniffing import KeyExtractedEvent
from whad.common.sniffing import EventsManager
from whad.hub.dot15d4 import RawPduReceived, PduReceived
from whad.hub.message import AbstractPacket
from whad.exceptions import WhadDeviceDisconnected
import logging

logger = logging.getLogger(__name__)

class Sniffer(RF4CE, EventsManager):
    """
    RF4CE Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device, configuration=SnifferConfiguration()):
        RF4CE.__init__(self, device)
        EventsManager.__init__(self)


        self.__configuration = configuration
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
        if (
            self.__configuration.audio and
            self.__configuration.audio_file is not None and
            self.__configuration.audio_file
        ):
            self.__audio_stream.output_filename = self.__configuration.audio_file
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
        #self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    def process_packet(self, packet):

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
                    metadata = packet.metadata
                    packet = decrypted
                    packet.metadata = metadata
                    if self.__configuration.audio:
                        self.__audio_stream.process_packet(packet)

            except MissingCryptographicMaterial:
                pass
        return packet

    def sniff(self):
        try:
            while True:
                if self.support_raw_pdu():
                    message_type = RawPduReceived
                else:
                    message_type = PduReceived

                message = self.wait_for_message(filter=message_filter(message_type), timeout=.1)
                if message is not None and issubclass(message, AbstractPacket):
                    packet = message.to_packet()
                    packet = self.process_packet(packet)

                    self.monitor_packet_rx(packet)

                    yield packet
        except WhadDeviceDisconnected:
            return
