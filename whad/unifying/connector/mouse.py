"""
This module provides the :class:`whad.unifying.connector.mouse.Mouse` class
that behaves like a Logitech Unifying mouse. This class is able to synchronize
with a specific dongle and send valid mouse and wheel moves as well as clicks.

This connector must be used with a compatible Logitech Unifying device.
"""
from whad.device import WhadDevice
from whad.unifying.connector import Unifying
from whad.esb.stack import ESBStack
from whad.unifying.stack import UnifyingApplicativeLayer, UnifyingRole, ClickType
from whad.exceptions import UnsupportedCapability


class Mouse(Unifying):
    """
    Logitech Unifying Mouse interface for compatible WHAD device.
    """

    def __init__(self, device: WhadDevice):
        """Logitech mouse initialisation

        :param device: WHAD device
        :type device: :class:`whad.device.WhadDevice`
        """
        super().__init__(device)

        self.__channel = 5
        self.__address = "ca:e9:06:ec:a4"
        self.__started = False
        ESBStack.add(UnifyingApplicativeLayer)
        self.__stack = ESBStack(self)
        # Check if device can choose its own address
        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        # Check if device can perform mouse simulation
        if not self.can_be_mouse():
            raise UnsupportedCapability("MouseSimulation")

        self._enable_role()


    def lock(self):
        """Lock mouse onto current channel.
        """
        return self.__stack.app.lock_channel()

    def unlock(self):
        """Unlock mouse from current channel.
        """
        return self.__stack.app.unlock_channel()

    def _enable_role(self):
        """Enable mouse role.
        """
        if self.__started:
            super().stop()
        self.set_node_address(self.__address)
        self.enable_mouse_mode(channel=self.__channel)
        self.__stack.app.role = UnifyingRole.MOUSE
        if self.__started:
            super().start()

    @property
    def channel(self) -> int:
        """Retrieve current channel.

        :return: current channel number
        :rtype: int
        """
        return self.__channel

    @channel.setter
    def channel(self, channel: int = 5):
        """Select channel.

        :param channel: channel to select (0-100)
        :type channel: int
        """
        self.__channel = channel
        self._enable_role()

    def start(self):
        """Start mouse emulation
        """
        self.__started = True
        self._enable_role()

    def stop(self):
        """Stop mouse emulation
        """
        self.__started = False
        self.unlock()
        super().stop()

    @property
    def stack(self):
        return self.__stack

    @property
    def address(self) -> ESBStack:
        """Retrieve the underlying stack

        :return: Underlying ESB stack instance
        :rtype: :class:`whad.esb.stack.ESBStack`
        """
        return self.__address

    @address.setter
    def address(self, address: str):
        """Set mouse address

        :param address: Mouse ESB address
        :type address: str
        """
        self.__address = address
        self._enable_role()

    def on_pdu(self, packet):
        """ESB packet handler. Feed the underlying ESB stack.
        """
        self.__stack.on_pdu(packet)

    def synchronize(self, timeout: float = 10.0) -> bool:
        """Synchronize with target mouse.

        :param timeout: timeout in seconds
        :type timeout: float
        :return: ``True`` if synchronization succeeded, ``False`` otherwise
        :rtype: bool
        """
        return self.__stack.ll.synchronize(timeout=timeout)

    def move(self, x: int, y: int):
        """Send a move event to the target mouse dongle.

        :param x: Delta X in ticks
        :type x: int
        :param y: Delta Y in ticks
        :type y: int
        """
        return self.__stack.app.move_mouse(x, y)

    def left_click(self):
        """Send a left click to the target mouse dongle.
        """
        return self.__stack.app.click_mouse(type=ClickType.LEFT)

    def right_click(self):
        """Send a right click to the target mouse dongle.
        """
        return self.__stack.app.click_mouse(type=ClickType.RIGHT)

    def middle_click(self):
        """Send a middle click to the target mouse dongle.
        """
        return self.__stack.app.click_mouse(type=ClickType.MIDDLE)

    def wheel_up(self):
        """Send a wheel up event to target mouse dongle.
        """
        return self.__stack.app.wheel_mouse(x=0, y=1)

    def wheel_down(self):
        """Send a wheel down event to target mouse dongle.
        """
        return self.__stack.app.wheel_mouse(x=0, y=-1)

    def wheel_right(self):
        """Send a wheel right event to target mouse dongle.
        """
        return self.__stack.app.wheel_mouse(x=1, y=0)

    def wheel_left(self):
        """Send a wheel left event to target mouse dongle.
        """
        return self.__stack.app.wheel_mouse(x=-1, y=0)
