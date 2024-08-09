from whad.esb.connector import ESB, PTX
from whad.esb.stack import ESBStack
from whad.exceptions import UnsupportedCapability, WhadDeviceDisconnected
from whad.esb.injecting import InjectionConfiguration
from whad.helpers import message_filter, is_message_type
from time import sleep, time


class Injector(PTX):
    """
    Enhanced ShockBurst Injector interface.
    """
    def __init__(self, device):
        super().__init__(device)
        self._synced = False
        self._configuration = InjectionConfiguration()
        self._injecting = False
        #self.start()

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

    def on_pdu(self, pdu):
        if self._injecting:
            return
        else:
            return super().on_pdu(pdu)

    def inject(self, packet):
        if hasattr(packet, "address") and packet.address != self.address:
            self.stop()
            self.address = packet.address
            self.start()
        if self.__configuration.synchronize:
            if not self._synced:
                self.synchronize()
                self._injecting = True
                while not self.send(packet, channel=self.channel, address=self.address):
                    self._injecting = False
                    self.synchronize()
                self._synced = True
                return True
            else:
                success = self.send(packet, channel=self.channel, address=self.address)
                return success
        else:
            success = self.send(packet, channel=self.__configuration.channel, address=self.address)
