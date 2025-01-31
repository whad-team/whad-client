import logging

from scapy.packet import Packet
from whad.wirelesshart.connector import WirelessHart
from whad.wirelesshart.sniffing import SnifferConfiguration
from whad.scapy.layers.wirelesshart import WirelessHart_Network_Security_SubLayer_Hdr
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter
from whad.wirelesshart.crypto import WirelessHartDecryptor
from whad.common.sniffing import EventsManager
from whad.hub.dot15d4 import RawPduReceived, PduReceived
from whad.hub.message import AbstractPacket
from whad.exceptions import WhadDeviceDisconnected
from whad.device import WhadDevice

logger = logging.getLogger(__name__)

class Sniffer(WirelessHart, EventsManager):
    """
    Wireless Hart Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device: WhadDevice):
        """Sniffer initialization.

        :param device: Device to use for sniffing
        :type device: WhadDevice
        """
        WirelessHart.__init__(self, device)
        EventsManager.__init__(self)

        self.__decryptor = WirelessHartDecryptor()
        self.__configuration = SnifferConfiguration()
        
        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _enable_sniffing(self):
        for key in self.__configuration.keys:
            self.__decryptor.add_key(key)
        self.sniff_wirelesshart(channel=self.__configuration.channel)

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

        :param channel: new Wireless Hart channel to use
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
        """Process received Wireless Hart packet.

        :param packet: received packet
        :type packet: :class:`scapy.packet.Packet`
        :return: received packet
        :rtype: :class:`scapy.packet.Packet`
        """
        if WirelessHart_Network_Security_SubLayer_Hdr in packet and self.__configuration.decrypt:
            decrypted, success = self.__decryptor.attempt_to_decrypt(packet)
            if success:
                packet = decrypted 
                packet.metadata.decrypted = True
                
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