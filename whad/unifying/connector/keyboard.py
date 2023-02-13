from whad.unifying.connector import Unifying
from whad.esb.stack import ESBStack
from whad.unifying.stack import UnifyingApplicativeLayerManager, UnifyingRole, MultimediaKey
from whad.exceptions import UnsupportedCapability


class Keyboard(Unifying):
    """
    Logitech Unifying Keyboard interface for compatible WHAD device.
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

        # Check if device can perform keyboard simulation
        if not self.can_be_keyboard():
            raise UnsupportedCapability("KeyboardSimulation")

        self._enable_role()


    def _enable_role(self):
        if self.__started:
            super().stop()
        self.set_node_address(self.__address)
        self.enable_keyboard_mode(channel=self.__channel)
        self.__stack.app.role = UnifyingRole.KEYBOARD
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
        self.unlock()
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

    def synchronize(self,timeout=10):
        return self.__stack.ll.synchronize(timeout=10)

    def lock(self):
        return self.__stack.app.lock_channel()

    def unlock(self):
        return self.__stack.app.unlock_channel()

    def send_text(self, text):
        for key in text:
            self.send_key(key)

    def send_key(self, key, ctrl=False, alt=False, shift=False, gui=False):
        if self.key is not None:
            return self.__stack.app.encrypted_keystroke(key, ctrl=ctrl, alt=alt, shift=shift, gui=gui)
        else:
            return self.__stack.app.unencrypted_keystroke(key, ctrl=ctrl, alt=alt, shift=shift, gui=gui)

    def volume_up(self):
        return self.__stack.app.multimedia_keystroke(MultimediaKey.VOLUME_UP)

    def volume_down(self):
        return self.__stack.app.multimedia_keystroke(MultimediaKey.VOLUME_DOWN)

    def volume_toggle(self):
        return self.__stack.app.multimedia_keystroke(MultimediaKey.VOLUME_TOGGLE)
