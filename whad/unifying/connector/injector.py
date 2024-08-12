from whad.unifying.connector import Unifying, Mouse
from whad.esb.stack import ESBStack
from whad.unifying.stack import UnifyingApplicativeLayer
from whad.exceptions import UnsupportedCapability, WhadDeviceDisconnected
from whad.unifying.injecting import InjectionConfiguration
from whad.helpers import message_filter, is_message_type
from time import sleep, time


class Injector(Mouse):
    """
    Logitech Unifying Injector interface.
    """
    def __init__(self, device):
        super().__init__(device)
        self._autosync = True
        self._synced = False
        self.__configuration = InjectionConfiguration()
        self._injecting = False
        self.start()

    @property
    def configuration(self) -> InjectionConfiguration:
        """Retrieve this injector configuration.
        """
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration: InjectionConfiguration):
        """Set the injector configuration.
        """
        self.__configuration = new_configuration
        if self.__configuration.address is not None:
            self.address = self.__configuration.address

    def on_pdu(self, pdu):
        if self._injecting:
            return
        else:
            return super().on_pdu(pdu)

    def inject(self, packet):
        if hasattr(packet, "address") and packet.address != self.address:
            self.address = packet.address
        elif hasattr(packet, "metadata") and hasattr(packet.metadata, "address"):
            self.address = packet.metadata.address

        if self.__configuration.synchronize:
            if not self._synced:
                if self.synchronize():
                    self.lock()
                self._injecting = True
                while not self.send(packet, channel=self.channel, address=self.address):
                    self._injecting = False
                    self.unlock()
                    if self.synchronize():
                        self.lock()
                self._synced = True
                return True
            else:
                success = self.send(packet, channel=self.channel, address=self.address)
                return success
        else:
            success = self.send(packet, channel=self.__configuration.channel, address=self.address)
