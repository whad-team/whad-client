from time import time
from typing import Generator

from scapy.packet import Packet

from whad.esb.connector import ESB
from whad.esb.sniffing import SnifferConfiguration
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type
from whad.common.sniffing import EventsManager
from whad.hub.esb import PduReceived, RawPduReceived
from whad.hub.message import AbstractPacket

class Sniffer(ESB, EventsManager):
    """
    Enhanced ShockBurst Sniffer interface for compatible WHAD device.
    """
    def __init__(self, device):
        ESB.__init__(self, device)
        EventsManager.__init__(self)

        self.__configuration = SnifferConfiguration()

        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _enable_sniffing(self):
        if self.__configuration.scanning:
            channel = None
        else:
            channel = self.__configuration.channel

        ack = self.__configuration.acknowledgements
        address = self.__configuration.address

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


    def available_actions(self, filter=None):
        actions = []
        return [action for action in actions if filter is None or isinstance(action, filter)]

    def sniff(self, timeout: float = None) -> Generator[Packet, None, None]:
        """Sniff packets

        :param timeout: Number of seconds after which sniffing will stop, uninterrupted if set to None
        :type timeout: float
        """
        # Determine message type
        if self.support_raw_pdu():
            message_type = RawPduReceived
        else:
            message_type = PduReceived

        # Sniff packets
        start = time()

        while True:

            # Exit if timeout is set and reached
            if timeout is not None and (time() - start >= timeout):
                break

            if self.support_raw_pdu():
                message_type = RawPduReceived
            else:
                message_type = PduReceived

            message = self.wait_for_message(filter=message_filter(message_type), timeout=.1)
            if message is not None and issubclass(message, AbstractPacket):
                packet = message.to_packet()
                self.monitor_packet_rx(packet)
                yield packet
