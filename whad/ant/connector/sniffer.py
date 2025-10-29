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

    def __init__(self, device, configuration=SnifferConfiguration()):
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

    @property
    def network_key(self):
        return self.__configuration.network_key

    @network_key.setter
    def network_key(self, key):
        self.stop()
        self.__configuration.network_key = key
        self._enable_sniffing()
        
    @property
    def device_number(self):
        return self.__configuration.device_number

    @device_number.setter
    def device_number(self, device_number):
        self.stop()
        self.__configuration.device_number = device_number
        self._enable_sniffing()
            
    @property
    def device_type(self):
        return self.__configuration.device_type

    @device_type.setter
    def device_type(self, device_type):
        self.stop()
        self.__configuration.device_type = device_type
        self._enable_sniffing()

    @property
    def transmission_type(self):
        return self.__configuration.transmission_type

    @transmission_type.setter
    def transmission_type(self, transmission_type):
        self.stop()
        self.__configuration.transmission_type = transmission_type
        self._enable_sniffing()

    @property
    def channel(self):
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel=57):
        #self.stop()
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
        if ANT_FS_Link_Command_Packet in packet:
            self.channel = packet.frequency
            print("[i] Hopping to channel "+str(packet.frequency))
        return packet

    def sniff(self, timeout: float = None) -> Generator[Packet, None, None]:
        """Sniff ANT packets out of thin air.

        :param timeout: Number of seconds after which sniffing will stop. Wait
                        forever if set to `None`.
        :type timeout: float
        """
        start = time()
        try:
            while True:
                if self.support_raw_pdu():
                    message_type = RawPduReceived
                else:
                    message_type = PduReceived

                message = self.wait_for_message(keep=message_filter(message_type), timeout=.1)
                if message is not None and issubclass(message, AbstractPacket):
                    packet = message.to_packet()
                    if packet is not None:
                        packet = self.process_packet(packet)
                        self.monitor_packet_rx(packet)
                        yield packet

                # Check if timeout has been reached
                if timeout is not None:
                    if time() - start >= timeout:
                        break
        except WhadDeviceDisconnected:
            return
