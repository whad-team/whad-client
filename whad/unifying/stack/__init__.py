"""
Logitech Unifying applicative layer.
"""
from enum import IntEnum
from whad.scapy.layers.unifying import Logitech_Unifying_Hdr, Logitech_Mouse_Payload, Logitech_Set_Keepalive_Payload
from whad.unifying.hid import LogitechUnifyingMouseMovementConverter

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

    def send_message(self, message):
        return self.__llm.send_data(Logitech_Unifying_Hdr()/message)

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
            raise RequiredImplementation("TransmittingKeepAlives")

    def move_mouse(self, x, y):

        self.send_message(
            Logitech_Mouse_Payload(
                LogitechUnifyingMouseMovementConverter.get_hid_data_from_coordinates(x, y)
            )
        )

    def on_data(self, data):
        pass

    def on_acknowledgement(self, ack):
        print("acked")
