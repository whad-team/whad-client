"""
This module provides the :class:`whad.unifying.connector.sniffer.Sniffer` class
that allows Logitech Unifying packets sniffing.



"""
import logging

from time import time
from typing import Generator, List
from scapy.packet import Packet

from whad.device import WhadDevice
from whad.exceptions import WhadDeviceDisconnected
from whad.unifying.connector import Unifying
from whad.unifying.sniffing import SnifferConfiguration, KeyExtractedEvent
from whad.unifying.crypto import LogitechUnifyingDecryptor, LogitechUnifyingKeyDerivation
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter
from whad.hub.unifying import RawPduReceived, PduReceived
from whad.common.sniffing import EventsManager
from whad.scapy.layers.unifying import Logitech_Unifying_Hdr, Logitech_Encrypted_Keystroke_Payload
from whad.hub.message import AbstractPacket

logger = logging.getLogger(__name__)

class Sniffer(Unifying, EventsManager):
    """
    Logitech Unifying Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device: WhadDevice):
        """Sniffer initialization.

        :param device: WHAD device to use
        :type device: :class:`whad.device.WhadDevice`
        """
        Unifying.__init__(self, device)
        EventsManager.__init__(self)

        self.__configuration = SnifferConfiguration()
        self.__decryptor = LogitechUnifyingDecryptor()
        self.__key_derivation = LogitechUnifyingKeyDerivation()

        self.__addresses = []
        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")


    def _enable_sniffing(self):
        """Enable sniffing.

        This method takes the current sniffing configuration and configure the
        hardware accordingly.
        """
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
        """Current sniffing configuration accessor.
        """
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration) -> SnifferConfiguration:
        """Sniffing configuration setter.

        :return: Sniffing configuration object
        :rtype: :class:`whad.unifying.sniffing.SnifferConfiguration`
        """
        self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    @property
    def channel(self) -> int:
        """Retrieve current channel.

        :return: current channel
        :rtype: int
        """
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel: int = 11):
        """Sniffing channel setter.

        :param channel: Channel to use
        :type channel: int
        """
        self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()

    def add_key(self, key: bytes):
        """Add encryption key to the curret sniffing configuration.

        :param key: Key to add
        :type key: bytes
        """
        self.stop()
        self.__configuration.keys.append(key)
        self._enable_sniffing()

    def clear_keys(self):
        """Remove all registered keys from current sniffing configuration.
        """
        self.stop()
        self.__configuration.keys = []
        self._enable_sniffing()

    @property
    def decrypt(self):
        """Current sniffing decryption flag accessor.
        """
        return self.__configuration.decrypt

    @decrypt.setter
    def decrypt(self, decrypt: bool):
        """Enable or disable decryption in current sniffing configuration.
        """
        self.stop()
        self.__configuration.decrypt = decrypt
        self._enable_sniffing()

    @property
    def address(self):
        """Target address accessor.
        """
        return self.__configuration.address

    @address.setter
    def address(self, address: str):
        """Target address setter.

        :param address: target address
        :type address: str
        """
        self.stop()
        self.__configuration.address = address
        self._enable_sniffing()

    @property
    def scanning(self):
        """Current sniffing configuration scanning flag accessor.
        """
        return self.__configuration.scanning

    @scanning.setter
    def scanning(self, scanning: bool):
        """Enable or disable scanning.

        :param scanning: Enable scanning if set to True, disable it if False
        :type scanning: bool
        """
        self.stop()
        self.__configuration.scanning = scanning
        self._enable_sniffing()

    def available_actions(self, filter=None) -> List:
        """Identify available actions.
        """
        actions = []
        return [action for action in actions if filter is None or isinstance(action, filter)]

    def process_packet(self, packet):
        """Implement the packet decryption if needed.
        """

        if self.__configuration.pairing:
            self.__key_derivation.process_packet(packet)
            if self.__key_derivation.key is not None:
                logger.info("[i] New key extracted: ", self.__key_derivation.key.hex())
                self.trigger_event(KeyExtractedEvent(self.__key_derivation.key))
                self.add_key(self.__key_derivation.key)
                self.__key_derivation.reset()

        if Logitech_Encrypted_Keystroke_Payload in packet and self.__configuration.decrypt:
            decrypted, success = self.__decryptor.attempt_to_decrypt(packet)
            if success:
                packet.decrypted = decrypted
                # Replace packet if decrypted
                decrypted_packet = packet.copy()
                decrypted_packet.metadata = packet.metadata
                decrypted_packet[Logitech_Unifying_Hdr].remove_payload()
                decrypted_packet.payload = decrypted
                packet = decrypted_packet
                # packet.checksum = None
                packet.metadata = decrypted_packet.metadata
                packet.metadata.decrypted = True
                return packet

        return packet


    def sniff(self, timeout: float = None) -> Generator[Packet, None, None]:
        """Sniff Logitech Unifying packets

        :param timeout: Number of seconds after which sniffing stops, uninterrupted if set to None
        :type timeout: float
        """
        # Determine message type
        if self.support_raw_pdu():
            message_type = RawPduReceived
        else:
            message_type = PduReceived

        # Sniff packets
        start = time()

        try:
            while True:

                # Exit if timeout is set and reached
                if timeout is not None and (time() - start >= timeout):
                    break

                message = self.wait_for_message(filter=message_filter(message_type), timeout=.1)
                if message is not None and issubclass(message, AbstractPacket):
                    packet = message.to_packet()

                    packet = self.process_packet(packet)
                    self.monitor_packet_rx(packet)
                    yield packet
        except WhadDeviceDisconnected:
            return
