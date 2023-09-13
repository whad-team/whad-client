from whad.unifying.connector import Unifying
from whad.esb.stack import ESBStack
from whad.unifying.stack import UnifyingApplicativeLayer, UnifyingRole
from whad.exceptions import UnsupportedCapability


class Dongle(Unifying):
    """
    Logitech Unifying Dongle interface for compatible WHAD device.
    """
    def __init__(self, device, **kwargs):
        super().__init__(device)

        self.__channel = 5
        self.__address = "ca:e9:06:ec:a4"
        self.__started = False
        ESBStack.add(UnifyingApplicativeLayer)
        self.__stack = ESBStack(self)

        for name, callback in kwargs.items():
            if name.startswith("on_"):
                self.__stack.app.callbacks[name] = callback

        # Check if device can choose its own address
        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        # Check if device can perform dongle simulation
        if not self.can_be_dongle():
            raise UnsupportedCapability("DongleSimulation")

        self._enable_role()


    def _enable_role(self):
        if self.__started:
            super().stop()
        self.set_node_address(self.__address)
        self.enable_dongle_mode(channel=self.__channel)
        self.__stack.app.role = UnifyingRole.DONGLE
        if self.__started:
            super().start()

    @property
    def channel(self):
        return self.__channel

    @channel.setter
    def channel(self, channel=5):
        self.__channel = channel
        self._enable_role()

    @property
    def key(self):
        return self.__stack.app.key

    @key.setter
    def key(self, key):
        self.__stack.app.key = key

    @property
    def aes_counter(self):
        return self.__stack.app.aes_counter

    @aes_counter.setter
    def aes_counter(self,aes_counter):
        self.__stack.app.aes_counter = aes_counter

    def start(self):
        self.__started = True
        self._enable_role()

    def stop(self):
        self.__started = False
        super().stop()

    @property
    def stack(self):
        return self.__stack

    @property
    def address(self):
        return self.__address

    @address.setter
    def address(self, address):
        self.__address = address
        self._enable_role()

    def wait_synchronization(self):
        return self.__stack.app.wait_synchronization()

    def wait_wakeup(self):
        return self.__stack.app.wait_wakeup()

    def on_pdu(self, packet):
        self.__stack.on_pdu(packet)

    def stream(self):
        for pdu in self.__stack.ll.data_stream():
            yield pdu
