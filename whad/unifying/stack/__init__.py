"""
Logitech Unifying applicative layer.
"""
from whad.scapy.layers.unifying import Logitech_Unifying_Hdr, Logitech_Mouse_Payload, Logitech_Set_Keepalive_Payload, \
    Logitech_Keepalive_Payload, Logitech_Unencrypted_Keystroke_Payload
from whad.unifying.hid import LogitechUnifyingMouseMovementConverter, LogitechUnifyingKeystrokeConverter, InvalidHIDData
from whad.unifying.stack.constants import UnifyingRole, ClickType
from time import sleep
from threading import Thread


class UnifyingApplicativeLayerManager:
    """
    This class handles the logic of Logitech Unifying protocol, used by Logitech mices and keyboards.
    The protocol is an application layer built over the Enhanced ShockBurst protocol, provided by Nordic SemiConductors.
    """
    def __init__(self, llm, role=UnifyingRole.DONGLE):
        self.__llm = llm
        self.__role = role
        self.__locale = "fr"
        self.__transmit_timeouts = False
        self.__timeout_thread = None

    @property
    def locale(self):
        return self.__locale

    @locale.setter
    def locale(self, value):
        self.__locale = value

    def _start_timeout_thread(self):
        self._stop_timeout_thread()
        self.__transmit_timeouts = True
        self.__timeout_thread = Thread(target=self._transmit_timeouts_thread, daemon=True)
        self.__timeout_thread.start()

    def _stop_timeout_thread(self):
        if self.__timeout_thread is not None:
            self.__transmit_timeouts = False
            self.__timeout_thread.join()
            self.__timeout_thread = None

    def _transmit_timeouts_thread(self):
        try:
            if self.__transmit_timeouts:
                self.send_message(Logitech_Set_Keepalive_Payload(timeout=1250), acknowledged=False)
            while self.__transmit_timeouts:
                self.send_message(Logitech_Keepalive_Payload(timeout=1250), acknowledged=False)
                sleep(0.01)
        except:
            pass

    def send_message(self, message, acknowledged=True):
        return self.__llm.send_data(Logitech_Unifying_Hdr()/message, acknowledged=acknowledged)

    def __del__(self):
        self._stop_timeout_thread()

    @property
    def role(self):
        return self.__role

    @role.setter
    def role(self, role):
        self.__role = role

    def enable_timeouts(self):
        if self.__role == UnifyingRole.DONGLE:
            raise RequiredImplementation("WaitingKeepAlives")
        else:
            self._start_timeout_thread()

    def lock_channel(self):
        if self.__timeout_thread is None:
            self.enable_timeouts()

    def move_mouse(self, x, y):
        self.lock_channel()
        try:
            answer = self.send_message(
                Logitech_Mouse_Payload(
                    movement=LogitechUnifyingMouseMovementConverter.get_hid_data_from_coordinates(x, y)
                )
            )
            return answer is not None
        except InvalidHIDData:
            return False

    def click_mouse(self, type=ClickType.RIGHT):
        self.lock_channel()
        answer = self.send_message(
            Logitech_Mouse_Payload(
                button_mask=int(type)
            )
        )
        return answer is not None

    def wheel_mouse(self, x, y):
        self.lock_channel()
        answer = self.send_message(
            Logitech_Mouse_Payload(
                button_mask=0,
                movement='',
                wheel_x=x,
                wheel_y=y
            )
        )
        return answer is not None

    def unencrypted_keystroke(self, key, ctrl=False, alt=False, shift=False, gui=False):
        self.lock_channel()
        try:
            answer_press = self.send_message(
                Logitech_Unencrypted_Keystroke_Payload(
                    hid_data=LogitechUnifyingKeystrokeConverter.get_hid_data_from_key(
                        key,
                        ctrl=False,
                        alt=False,
                        shift=False,
                        gui=False,
                        locale=self.__locale
                    )
                )
            )
            sleep(0.005)
            answer_release = self.send_message(
                Logitech_Unencrypted_Keystroke_Payload(
                    hid_data=b"\x00"*7
                )
            )
            return answer_press is not None and answer_release is not None

        except InvalidHIDData:
            return False

    def on_synchronized(self):
        print("[i] Synchronized !")


    def on_desynchronized(self):
        print("[i] Desynchronized, resync...")

    def on_data(self, data):
        pass

    def on_acknowledgement(self, ack):
        print("acked")
