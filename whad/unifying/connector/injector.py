from whad.unifying.connector import Unifying, Mouse
from whad.esb.stack import ESBStack
from whad.unifying.stack import UnifyingApplicativeLayer
from whad.exceptions import UnsupportedCapability, WhadDeviceDisconnected
from whad.hub.message import AbstractPacket
from whad.hub.unifying import RawPduReceived, PduReceived
from whad.helpers import message_filter, is_message_type
from time import sleep, time


class Injector(Mouse):
    """
    Logitech Unifying Injector interface.
    """
    def __init__(self, device):
        super().__init__(device)
        self._autosync = True
        self._injecting = False
        self.start()
    @property
    def autosync(self):
        return self._autosync


    @autosync.setter
    def autosync(self, value):
        self._autosync = value
        self._synced = False

    def on_pdu(self, pdu):
        if self._injecting:
            return
        else:
            return super().on_pdu(pdu)

    def inject(self, packet):
        if hasattr(packet, "address") and packet.address != self.address:
            self.address = packet.address

        if self.autosync and not self._synced:
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
'''
class Injector(Unifying):
    """
    Logitech Unifying Dongle interface for compatible WHAD device.
    """
    def __init__(self, device, **kwargs):
        super().__init__(device)

        self.__channel = None
        self.__autosync = True
        self.__address = "ca:e9:06:ec:a4"

        # Check if device can choose its own address
        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        # Check if device can send data
        if not self.can_send():
            raise UnsupportedCapability("Send")

        self.enable_synchronous(True)
        super().stop()
        self.set_node_address(self.__address)
        super().start()

    @property
    def autosync(self):
        return self.__autosync

    @autosync.setter
    def autosync(self, autosync):
        self.__autosync = autosync

    @property
    def channel(self):
        return self.__channel

    @channel.setter
    def channel(self, channel=5):
        self.__channel = channel

    @property
    def address(self):
        return self.__address

    @address.setter
    def address(self, address):
        self.__address = address
        super().stop()
        self.set_node_address(self.__address)
        super().start()

    def synchronize(self, timeout=None):
        self.__sync = False
        super().stop()
        super().sniff(channel=None, show_acknowledgements=True, address=self.address)
        super().start()
        # Determine message type
        if self.support_raw_pdu():
            message_type = RawPduReceived
        else:
            message_type = PduReceived

        while True:

            # Exit if timeout is set and reached
            if timeout is not None and (time() - start >= timeout):
                break

            message = self.wait_for_message(filter=message_filter(message_type), timeout=.1)
            if message is not None and issubclass(message, AbstractPacket):
                self.channel = message.channel
                return True
        return False


    def inject(self, packet):
        if self.channel is None or self.autosync:
            self.channel = None
            self.synchronize()
            print("sync", self.channel)
        success = self.send(packet, channel=self.channel, address=self.address)
        if not success and self.autosync:
            self.channel = None
            while self.channel is None:
                self.synchronize()
            print(self.channel)
            success = self.send(packet, channel=self.channel, address=self.address)
            if success:
                return success
        return success
'''
