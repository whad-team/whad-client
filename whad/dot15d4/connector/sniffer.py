"""Dot15d4 sniffing module

This module provides a Sniffer class for Dot15d4 protocol, that is used by
`whad-sniff` to sniff dot15d4-based protocols.
"""
from typing import Generator, List

# Required by type hints
from scapy.packet import Packet

from whad.dot15d4.connector import Dot15d4
from whad.dot15d4.sniffing import SnifferConfiguration
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type
from whad.common.sniffing import EventsManager
from whad.hub.dot15d4 import RawPduReceived, PduReceived


class Sniffer(Dot15d4, EventsManager):
    """
    802.15.4 Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device):
        """Initialize our sniffer.
        """
        Dot15d4.__init__(self, device)
        EventsManager.__init__(self)

        self.__configuration = SnifferConfiguration()

        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _enable_sniffing(self):
        self.sniff_dot15d4(channel=self.__configuration.channel)

    @property
    def configuration(self) -> SnifferConfiguration:
        """Retrieve this sniffer configuration.
        """
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration: SnifferConfiguration):
        """Set the sniffer configuration.
        """
        self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    @property
    def channel(self) -> int:
        """Retrieve the currently configured channel this sniffer is listening on.
        """
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel: int = 11):
        """Set current channel and start sniffing on it.
        """
        self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()


    def available_actions(self, filter=None) -> List:
        """Retrieve the possible actions on this sniffer.
        """
        actions = []
        return [action for action in actions if filter is None or isinstance(action, filter)]

    def sniff(self) -> Generator[Packet, None , None]:
        """Main sniffing loop.

        This method waits for raw PDUs or PDUs, depending on hardware capability, and report
        them to the caller by yielding Scapy packets created from sniffed PDUs. These packets
        also include metadata (reception timestamp, channel, ...).
        """
        while True:
            if self.support_raw_pdu():
                message_type = RawPduReceived
            else:
                message_type = PduReceived

            message = self.wait_for_message(filter=message_filter(message_type), timeout=.1)
            if message is not None:
                packet = message.to_packet()
                self.monitor_packet_rx(packet)
                yield packet
