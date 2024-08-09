"""
This module provides a :class:`Sniffer` class that derives from :class:`ESB`
to allow *Enhanced ShockBurst* frame sniffing. Sniffed frames are wrapped in
a dedicated *Scapy* layer and therefore are represented as *Scapy* packets.

This :class:`Sniffer` class is used by the generic `wsniff` utility when
*Enhanced ShockBurst* protocol is selected, and the associated
:class:`whad.esb.sniffing.SnifferConfiguration` class holds all the sniffing
parameters that can be set.

By default, the *Enhanced ShockBurst* sniffer sniffs packet on all channels by
looping from channel 0 to 100 over and over and capturing frames that match
the expected format.
"""
from time import time
from typing import Generator

from scapy.packet import Packet

from whad.device import WhadDevice
from whad.exceptions import WhadDeviceDisconnected
from whad.esb.connector import ESB
from whad.esb.sniffing import SnifferConfiguration
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter
from whad.common.sniffing import EventsManager
from whad.hub.esb import PduReceived, RawPduReceived
from whad.hub.message import AbstractPacket

class Sniffer(ESB, EventsManager):
    """
    Enhanced ShockBurst Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device: WhadDevice):
        ESB.__init__(self, device)
        EventsManager.__init__(self)

        self.__configuration = SnifferConfiguration()

        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _enable_sniffing(self):
        """Configure the underlying ESB connector.


        This method parses the current configuration and sets the underlying
        ESB connector properties accordingly before starting sniffing packets.
        """
        if self.__configuration.scanning:
            channel = None
        else:
            channel = self.__configuration.channel

        ack = self.__configuration.acknowledgements
        address = self.__configuration.address

        super().sniff(channel=channel, show_acknowledgements=ack, address=address)
        self.start()

    @property
    def configuration(self) -> SnifferConfiguration:
        """Current configuration getter.
        """
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        """Configuration setter.

        :param new_configuration: New configuration to apply.
        :type new_configuration: :class:`whad.esb.sniffing.SnifferConfiguration`
        """
        self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    @property
    def channel(self) -> int:
        """Channel getter.
        """
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel=11):
        """Channel setter.

        This method stops sniffing, update the current channel to the one
        specified into the configuration and then return to sniffing on this
        newly set channel.
        """
        self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()


    def sniff(self, channel: int = None, address: str = None, show_acknowledgements: bool = False,
              timeout: float = None) -> Generator[Packet, None, None]:
        """Update current sniffing configuration if required and sniff packets. This function
        returns after `timeout` seconds, if specified.

        :param channel: Channel to listen, None to iterate over all possible channels
        :type channel: int
        :param address: Device address to target
        :type address: str
        :param show_acknowledgements: Sniff packets acknowledgements if set to True (default: False)
        :type show_acknowledgements: bool
        :param timeout: Number of seconds after which sniffing will stop,
                        uninterrupted if set to None
        :type timeout: float
        """
        # Set channel, address and show ack if provided
        update_config_required = False
        if show_acknowledgements is not None:
            self.__configuration.acknowledgements = show_acknowledgements
            update_config_required = True
        if address is not None:
            self.__configuration.address = address
            update_config_required = True
        if channel is not None:
            self.__configuration.channel = channel

        # Update configuration if at least one parameter has been changed
        if update_config_required:
            self.stop()
            self._enable_sniffing()

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

                if self.support_raw_pdu():
                    message_type = RawPduReceived
                else:
                    message_type = PduReceived

                message = self.wait_for_message(filter=message_filter(message_type), timeout=.1)

                if message is not None and issubclass(message, AbstractPacket):
                    packet = message.to_packet()
                    self.monitor_packet_rx(packet)
                    yield packet

        # Handle device disconnection
        except WhadDeviceDisconnected:
            return
