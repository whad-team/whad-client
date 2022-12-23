from whad.unifying.connector import Unifying
from whad.esb.stack import ESBStack
from whad.unifying.stack import UnifyingApplicativeLayerManager, UnifyingRole
from whad.exceptions import UnsupportedCapability


class Mouse(Unifying):
    """
    Logitech Unifying Sniffer interface for compatible WHAD device.
    """
    def __init__(self, device):
        super().__init__(device)

        self.__channel = 5
        self.__address = "ca:e9:06:ec:a4"
        self.__started = False
        self.__stack = ESBStack(
            self,
            app_class = UnifyingApplicativeLayerManager
        )
        # Check if device can choose its own address
        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        # Check if device can perform mouse simulation
        if not self.can_be_mouse():
            raise UnsupportedCapability("MouseSimulation")

        self._enable_role()


    def _enable_role(self):
        if self.__started:
            super().stop()
        self.set_node_address(self.__address)
        self.enable_mouse_mode(channel=self.__channel)
        self.__stack.app.role = UnifyingRole.MOUSE
        if self.__started:
            super().start()
    @property
    def channel(self):
        return self.__channel

    @channel.setter
    def channel(self, channel=5):
        self.__channel = channel
        self._enable_role()

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

    def on_pdu(self, packet):
        self.__stack.on_pdu(packet)

    def synchronize(self, timeout=10):
        return self.__stack.ll.synchronize(timeout=10)

    def move(self, x, y):
        self.__stack.app.move_mouse(x, y)
