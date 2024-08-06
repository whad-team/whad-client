"""
This module provides the :class:`whad.unifying.keyboard.Keyboard` class that
behaves like a Logitech Unifying keyboard. This connector is able to synchronize
with an existing keyboard dongle and send spoofed events.
"""

from whad.device import WhadDevice
from whad.unifying.connector import Unifying
from whad.esb.stack import ESBStack
from whad.unifying.stack import UnifyingApplicativeLayer, UnifyingRole, MultimediaKey
from whad.exceptions import UnsupportedCapability


class Keyboard(Unifying):
    """
    Logitech Unifying Keyboard interface for compatible WHAD device.
    """

    def __init__(self, device: WhadDevice):
        """Initialisation

        :param device: WHAD device
        :type device: WhadDevice
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

        # Check if device can perform keyboard simulation
        if not self.can_be_keyboard():
            raise UnsupportedCapability("KeyboardSimulation")

        self._enable_role()


    def _enable_role(self):
        """Enable Unifying keyboard role.
        """
        if self.__started:
            super().stop()
        self.set_node_address(self.__address)
        self.enable_keyboard_mode(channel=self.__channel)
        self.__stack.app.role = UnifyingRole.KEYBOARD
        if self.__started:
            super().start()

    @property
    def channel(self) -> int:
        """Current channel in use

        :return: current channel in use
        :rtype: int
        """
        return self.__channel

    @channel.setter
    def channel(self, channel: int = 5):
        """Set channel

        :param channel: channel to use
        :type channel: int
        """
        self.__channel = channel
        self._enable_role()

    @property
    def key(self) -> bytes:
        """Current encryption key

        :return: encryption key
        :rtype: bytes
        """
        return self.__stack.app.key

    @key.setter
    def key(self, key: bytes):
        """Set encryption key

        :param key: encryption key to use
        :type key: bytes
        """
        self.__stack.app.key = key

    @property
    def aes_counter(self) -> int:
        """Current AES counter value

        :return: AES counter value
        :rtype: int
        """
        return self.__stack.app.aes_counter

    @aes_counter.setter
    def aes_counter(self,aes_counter: int):
        """Set AES counter value

        :param aes_counter: New AES counter value
        :type aes_counter: int
        """
        self.__stack.app.aes_counter = aes_counter

    def start(self):
        """Start keyboard mode
        """
        self.__started = True
        self._enable_role()

    def stop(self):
        """Stop keyboard mode
        """
        self.__started = False
        super().stop()

    @property
    def stack(self) -> ESBStack:
        """Current ESB stack in use

        :return: ESB stack instance
        :rtype: :class:`whad.esb.stack.ESBStack`
        """
        return self.__stack

    @property
    def address(self) -> str:
        """Current device address

        :return: current device address
        :rtype: str 
        """
        return self.__address

    @address.setter
    def address(self, address: str):
        """Set current device address

        :param address: Device address (5-byte ESB address)
        :rtype address: str
        """
        self.__address = address
        self._enable_role()

    def on_pdu(self, packet):
        """Unifying packet handler, feeds the underlying stack.
        """
        self.__stack.on_pdu(packet)

    def synchronize(self, timeout: float = 10.0) -> bool:
        """Synchronize with target device.

        :param timeout: timeout in seconds
        :type timeout: float
        :return: ``True`` if synchronization succeeded, ``False`` otherwise.
        :rtype: bool
        """
        return self.__stack.ll.synchronize(timeout=timeout)

    def lock(self):
        """Lock keyboard on current channel.
        """
        return self.__stack.app.lock_channel()

    def unlock(self):
        """Unlock keyboard from current channel.
        """
        return self.__stack.app.unlock_channel()

    def send_text(self, text: str):
        """Send a series of keystrokes.

        :param text: text to send
        :type text: str
        """
        for key in text:
            self.send_key(key)

    def send_key(self, key, ctrl: bool = False, alt: bool = False, shift: bool = False,
                 gui: bool = False) -> bool:
        """Send a keypress with modifiers.

        :param key: Key to send
        :type key: bytes
        :param ctrl: CONTROL key modifier enabled if set to ``True``
        :type ctrl: bool
        :param alt: ALT key modifier enabled if set to ``True``
        :type alt: bool
        :param shift: SHIFT key modifier enabled if set to ``True``
        :type shift: bool
        :param gui: GUI key modifier enabled if set to ``True``
        :type gui: bool
        :return: ``True`` if key has been successfully injected, ``False`` otherwise.
        :rtype: bool
        """
        if self.key is not None:
            return self.__stack.app.encrypted_keystroke(key, ctrl=ctrl, alt=alt,
                                                        shift=shift, gui=gui)
        else:
            return self.__stack.app.unencrypted_keystroke(key, ctrl=ctrl, alt=alt,
                                                          shift=shift, gui=gui)

    def volume_up(self) -> bool:
        """Send a volume up keypress.
        """
        return self.__stack.app.multimedia_keystroke(MultimediaKey.VOLUME_UP)

    def volume_down(self) -> bool:
        """Send a volume down keypress.
        """
        return self.__stack.app.multimedia_keystroke(MultimediaKey.VOLUME_DOWN)

    def volume_toggle(self) -> bool:
        """Send a volume toggle keypress.
        """
        return self.__stack.app.multimedia_keystroke(MultimediaKey.VOLUME_TOGGLE)
 