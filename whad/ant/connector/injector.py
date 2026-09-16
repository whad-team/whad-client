"""
WHAD ANT injection connector.

This module provides the `Injector` class for ANT-enable devices.
This class is used by `winject` to perform packet/PDU injection of ANT packets.
"""
from scapy.packet import Packet

from whad.ant.connector import ANT
from whad.ant.injecting import InjectionConfiguration
from whad.scapy.layers.ant import ANT_FS_Link_Command_Packet

class Injector(ANT):
    """
    ANT Injector interface.
    """
    def __init__(self, device):
        super().__init__(device)
        self._synced = False
        self._configuration = InjectionConfiguration()
        self._injecting = False
        
    @property
    def configuration(self) -> InjectionConfiguration:
        """Retrieve this injector configuration.
        """
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration: InjectionConfiguration):
        """Set the injector configuration.
        """
        self.stop()
        self.__configuration = new_configuration
        if self.__configuration.channel is not None:
            self.channel = self.__configuration.channel
        self.start()

    @property
    def channel(self):
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel=57):
        #self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()


    def on_pdu(self, packet: Packet):
        """Callback method to handle incoming packet

        :param packet: Incoming packet
        :type packet: Packet
        """
        # Let ANT class process the incoming packet.
        return super().on_pdu(packet)

    def inject(self, packet: Packet):
        """Perform packet injection.

        :param packet: Packet to inject
        :type packet: Packet
        """
        success = self.send(packet,channel_number=0xFF, rf_channel=self.__configuration.channel)
        if ANT_FS_Link_Command_Packet in packet:
            self.channel = packet.frequency
        return success