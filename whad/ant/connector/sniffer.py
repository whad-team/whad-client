import logging
from typing import Generator
from time import time

from scapy.packet import Packet

from whad.ant.connector import ANT
from whad.ant.sniffing import SnifferConfiguration
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type
from whad.common.sniffing import EventsManager
from whad.hub.ant import RawPduReceived, PduReceived
from whad.hub.message import AbstractPacket
from whad.exceptions import WhadDeviceDisconnected
from whad.scapy.layers.ant import ANT_FS_Link_Command_Packet


logger = logging.getLogger(__name__)

class Sniffer(ANT, EventsManager):
    """
    ANT Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device, configuration: SnifferConfiguration = SnifferConfiguration()):
        ANT.__init__(self, device)
        EventsManager.__init__(self)


        self.__configuration = configuration

        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _enable_sniffing(self):
        self.sniff_ant(
            device_number = self.__configuration.device_number, 
            device_type = self.__configuration.device_type, 
            transmission_type  = self.__configuration.transmission_type,
            network_key = self.__configuration.network_key, 
            rf_channel = self.__configuration.channel
        )

    def stop(self):
        """
        Stop the sniffer.
        """
        super().stop()
        
    @property
    def network_key(self) -> bytes:
        """
        Network key configuring the sniffer.
        """
        return self.__configuration.network_key

    @network_key.setter
    def network_key(self, key: bytes):
        self.stop()
        self.__configuration.network_key = key
        self._enable_sniffing()
        
    @property
    def device_number(self) -> int:
        """
        Device number to select.
        """
        return self.__configuration.device_number

    @device_number.setter
    def device_number(self, device_number: int):
        self.stop()
        self.__configuration.device_number = device_number
        self._enable_sniffing()
            
    @property
    def device_type(self) -> int:
        """
        Device type to select.
        """
        return self.__configuration.device_type

    @device_type.setter
    def device_type(self, device_type: int):
        self.stop()
        self.__configuration.device_type = device_type
        self._enable_sniffing()

    @property
    def transmission_type(self: int):
        """
        Transmission type to select.
        """
        return self.__configuration.transmission_type

    @transmission_type.setter
    def transmission_type(self, transmission_type: int):
        self.stop()
        self.__configuration.transmission_type = transmission_type
        self._enable_sniffing()


    @property
    def follow(self) -> int:
        """
        Boolean indicating if sniffer follows potential channel changes.
        """
        return self.__configuration.follow

    @follow.setter
    def follow(self, channel: bool = True):
        self.__configuration.follow = follow
        self._enable_sniffing()

    @property
    def channel(self) -> int:
        """
        RF Channel to select.
        """
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel: int = 57):
        self.__configuration.channel = channel
        self._enable_sniffing()


    @property
    def configuration(self) -> SnifferConfiguration:
        """
        Radio configuration in use.
        """
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration:SnifferConfiguration):
        #self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    def process_packet(self, packet : Packet):
        """
        Method processing the incoming packets.
        """
        # If we observe an ANT-FS Link Command, move to the RF channel indicated in the received packet.
        if ANT_FS_Link_Command_Packet in packet and self.configuration.follow:
            self.channel = packet.frequency
            # print("[i] Hopping to channel "+str(packet.frequency))
            
        return packet

    def sniff(self, timeout: float = None) -> Generator[Packet, None, None]:
        """Sniff ANT packets out of thin air.

        :param timeout: Number of seconds after which sniffing will stop. Wait
                        forever if set to `None`.
        :type timeout: float
        """
        start = time()
        try:
                if self.support_raw_pdu():
                    message_type = RawPduReceived
                else:
                    message_type = PduReceived

                for message in super().capture(messages=(message_type), timeout=timeout):
                    if message is not None:
                        packet = message.to_packet()
                        if packet is not None:
                            packet = self.process_packet(packet)
                            self.monitor_packet_rx(packet)
                            yield packet
                
        except WhadDeviceDisconnected:
            return
