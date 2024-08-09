import logging

from scapy.packet import Packet
from scapy.layers.zigbee import ZigbeeSecurityHeader
from whad.zigbee.connector import Zigbee
from whad.zigbee.sniffing import SnifferConfiguration, KeyExtractedEvent
from whad.zigbee.crypto import ZigbeeDecryptor, TouchlinkKeyManager, TransportKeyDistribution
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter
from whad.common.sniffing import EventsManager
from whad.hub.dot15d4 import RawPduReceived, PduReceived
from whad.hub.message import AbstractPacket
from whad.exceptions import WhadDeviceDisconnected
from whad.device import WhadDevice

logger = logging.getLogger(__name__)

class Sniffer(Zigbee, EventsManager):
    """
    Zigbee Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device: WhadDevice):
        """Sniffer initialization.

        :param device: Device to use for sniffing
        :type device: WhadDevice
        """
        Zigbee.__init__(self, device)
        EventsManager.__init__(self)


        self.__configuration = SnifferConfiguration()
        self.__decryptor = ZigbeeDecryptor()
        self.__touchlink_key_derivation = TouchlinkKeyManager()
        self.__transport_key_distribution = TransportKeyDistribution()
        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _enable_sniffing(self):
        for key in self.__configuration.keys:
            self.__decryptor.add_key(key)
        self.sniff_zigbee(channel=self.__configuration.channel)

    def add_key(self, key: bytes):
        """Add an encryption key to our sniffer.

        :param key: encryption key to add
        :type key: bytes
        """
        self.__configuration.keys.append(key)

    def clear_keys(self):
        """Clear all stored encryption keys.
        """
        self.__configuration.keys = []

    @property
    def decrypt(self) -> bool:
        """Decryption enabled
        """
        return self.__configuration.decrypt

    @decrypt.setter
    def decrypt(self, decrypt: bool):
        """Set decryption status
        """
        self.__configuration.decrypt = decrypt


    @property
    def channel(self) -> int:
        """Current channel
        """
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel: int = 11):
        """Set current channel.

        :param channel: new ZigBee channel to use
        :type channel: int
        """
        self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()


    @property
    def configuration(self) -> SnifferConfiguration:
        """Current sniffer configuration.
        """
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    def process_packet(self, packet: Packet):
        """Process received ZigBee packet.

        :param packet: received packet
        :type packet: :class:`scapy.packet.Packet`
        :return: received packet
        :rtype: :class:`scapy.packet.Packet`
        """
        if self.__touchlink_key_derivation.unencrypted_key is not None:
            logger.info("[i] New key extracted: %s",
                        self.__touchlink_key_derivation.unencrypted_key.hex())
            self.trigger_event(KeyExtractedEvent(self.__touchlink_key_derivation.unencrypted_key))
            self.add_key(self.__touchlink_key_derivation.unencrypted_key)
            self.__decryptor.add_key(self.__touchlink_key_derivation.unencrypted_key)
            self.__touchlink_key_derivation.reset()

        if self.__transport_key_distribution.transport_key is not None:
            logger.info(
                "[i] New key extracted: %s",
                self.__transport_key_distribution.transport_key.hex())
            self.trigger_event(KeyExtractedEvent(self.__transport_key_distribution.transport_key))
            self.add_key(self.__transport_key_distribution.transport_key)
            self.__decryptor.add_key(self.__transport_key_distribution.transport_key)
            self.__transport_key_distribution.reset()


        if ZigbeeSecurityHeader in packet and self.__configuration.decrypt:
            decrypted, success = self.__decryptor.attempt_to_decrypt(packet)
            if success:
                packet.data = decrypted
                packet.metadata.decrypted = True


        if self.__configuration.pairing:
            self.__touchlink_key_derivation.process_packet(packet)
            self.__transport_key_distribution.process_packet(packet)

        return packet

    def sniff(self):
        try:
            while True:
                if self.support_raw_pdu():
                    message_type = RawPduReceived
                else:
                    message_type = PduReceived

                message = self.wait_for_message(filter=message_filter(message_type), timeout=0.1)
                if message is not None and issubclass(message, AbstractPacket):
                    packet = message.to_packet()
                    self.monitor_packet_rx(packet)
                    packet = self.process_packet(packet)
                    yield packet
        except WhadDeviceDisconnected:
            return