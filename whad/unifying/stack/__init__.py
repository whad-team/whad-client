"""
Logitech Unifying applicative layer.
"""
from enum import IntEnum
from whad.scapy.layers.unifying import Logitech_Unifying_Hdr, Logitech_Mouse_Payload, Logitech_Set_Keepalive_Payload, Logitech_Keepalive_Payload
from whad.unifying.hid import LogitechUnifyingMouseMovementConverter
from time import sleep
from threading import Thread

class UnifyingRole(IntEnum):
    DONGLE = 0
    MOUSE = 1
    KEYBOARD = 2

class UnifyingApplicativeLayerManager:
    """
    This class handles the logic of Logitech Unifying protocol, used by Logitech mices and keyboards.
    The protocol is an application layer built over the Enhanced ShockBurst protocol, provided by Nordic SemiConductors.
    """
    def __init__(self, llm, role=UnifyingRole.DONGLE):
        self.__llm = llm
        self.__role = role
        self.__transmit_timeouts = False
        self.__timeout_thread = None

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

    def move_mouse(self, x, y):
        if self.__timeout_thread is None:
            self.enable_timeouts()

        answer = self.send_message(
            Logitech_Mouse_Payload(
                movement=LogitechUnifyingMouseMovementConverter.get_hid_data_from_coordinates(x, y)
            )
        )
        if answer:
            print("acked :)")

    def on_data(self, data):
        pass

    def on_acknowledgement(self, ack):
        print("acked")
