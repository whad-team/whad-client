from re import I
from typing import List

from scapy.packet import Packet
from scapy.layers.bluetooth import (
    ATT_Error_Response, ATT_Handle_Value_Indication, ATT_Hdr, ATT_Write_Request, ATT_Write_Response, ATT_Handle_Value_Notification,
)

from whad.ble.stack.att.constants import BleAttOpcode
from .procedure import BleClientProcedure

class ClientNotificationCheckProcedure(BleClientProcedure):
    """GATT client notification subscription procedure."""

    OPCODE = BleAttOpcode.HANDLE_VALUE_NOTIFICATION

    def __init__(self, handle: int):
        """Initialize a GATT client notfication check."""
        super().__init__([
            ATT_Write_Request(
                gatt_handle=handle,
                data=bytes([0x01, 0x00])
            )
        ])

    def process_request(self, request: Packet) -> List[Packet]:
        """Process incoming PDUs."""
        request.show()
        # Do we got an error ? Force state to ERROR and save
        # the error details. Procedure is considered terminated.
        if ATT_Error_Response in request:
            print(f"Error received while in state {self.get_state()}")
            self.set_result(request[ATT_Error_Response])
            self.set_state(self.states.ERROR)
            return []

        # We are expecting a write response following our Initial
        # write into the target attribute (CCC descriptor)
        if self.get_state() == self.states.INITIAL:
            if ATT_Hdr in request and request[ATT_Hdr].opcode == 0x13:
                print(f"Descriptor successfully modified, wait for notification ...")
                # Write response received, update state
                self.set_state(self.states.SUB_DONE)
                return []

        # Once subed to a characteristic, we are expecting a notification
        # to complete this procedure.
        if self.get_state() == self.states.SUB_DONE:
            # If we received a notification, everything is fine
            # and procedure is done.
            if ATT_Handle_Value_Notification in request:
                self.set_result(request[ATT_Handle_Value_Notification])
                self.set_state(self.states.DONE)
                return []

        # Default handler
        return []

class ClientIndicationCheckProcedure(BleClientProcedure):
    """GATT client indication subscription procedure."""

    OPCODE = BleAttOpcode.HANDLE_VALUE_INDICATION

    def __init__(self, handle: int):
        """Initialize a GATT client indication check."""
        super().__init__([
            ATT_Write_Request(
                gatt_handle=handle,
                data=bytes([0x02, 0x00])
            )
        ])

    def process_request(self, request: Packet) -> List[Packet]:
        """Process incoming PDUs."""
        request.show()
        # Do we got an error ? Force state to ERROR and save
        # the error details. Procedure is considered terminated.
        if ATT_Error_Response in request:
            print(f"Error received while in state {self.get_state()}")
            self.set_result(request[ATT_Error_Response])
            self.set_state(self.states.ERROR)
            return []

        # We are expecting a write response following our Initial
        # write into the target attribute (CCC descriptor)
        if self.get_state() == self.states.INITIAL:
            if ATT_Hdr in request and request[ATT_Hdr].opcode == 0x13:
                print(f"Descriptor successfully modified, wait for indication ...")
                # Write response received, update state
                self.set_state(self.states.SUB_DONE)
                return []

        # Once subed to a characteristic, we are expecting a indication
        # to complete this procedure.
        if self.get_state() == self.states.SUB_DONE:
            # If we received a notification, everything is fine
            # and procedure is done.
            if ATT_Handle_Value_Indication in request:
                print("SUCCESS")
                self.set_result(request[ATT_Handle_Value_Indication])
                self.set_state(self.states.DONE)
                return [ATT_Hdr(opcode=BleAttOpcode.HANDLE_VALUE_CONFIRMATION)]

        # Default handler
        return []

