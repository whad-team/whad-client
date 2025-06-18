"""
WHAD Enhanced ShockBurst injection connector.

This module provides the `Injector` class for ESB-enable devices.
This class is used by `winject` to perform packet/PDU injection into an
existing ESB connection, or simply send ESB packets in the air.
"""
from scapy.packet import Packet

from .base import PTX
from ..injecting import InjectionConfiguration

class Injector(PTX):
    """
    Enhanced ShockBurst Injector interface.
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
        if self.__configuration.address is not None:
            self.address = self.__configuration.address
        if self.__configuration.channel is not None:
            self.channel = self.__configuration.channel

        self.start()

    def on_pdu(self, packet: Packet):
        """Callback method to handle incoming packet

        :param packet: Incoming packet
        :type packet: Packet
        """
        # If we are injecting, do not process incoming packets.
        if self._injecting:
            return None

        # Let ESB class process the incoming packet.
        return super().on_pdu(packet)

    def inject(self, packet: Packet):
        """Perform packet injection.

        :param packet: Packet to inject
        :type packet: Packet
        """
        if hasattr(packet, "address") and packet.address != self.address:
            self.stop()
            self.address = packet.address
            self.start()

        if self.__configuration.synchronize:
            # Synchronize if not already sync'ed
            if not self._synced:
                self.synchronize()
                self._injecting = True
                while not self.send(packet, channel=self.channel, address=self.address):
                    self._injecting = False
                    self.synchronize()
                self._synced = True
                return True

            # If already synchronized, just send packet.
            return self.send(packet, channel=self.channel, address=self.address)

        return self.send(packet, channel=self.__configuration.channel, address=self.address)
