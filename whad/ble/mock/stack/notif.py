from re import I
from typing import List

from scapy.packet import Packet
from scapy.layers.bluetooth import (
    ATT_Error_Response, ATT_Write_Request, ATT_Write_Response, ATT_Handle_Value_Notification,
)
from .procedure import Procedure

class ClientNotificationCheckProcedure(Procedure):
    """GATT client notification subscription procedure."""

    # Declare an intermediate state
    STATE_SUB_DONE = Procedure.STATE_USER

    def __init__(self, handle: int):
        """Initialize a GATT client notfication check."""
        self.__handle = handle
        super().__init__([], 23)

    def initiate(self) -> List[Packet]:
        """Initiate a GATT client notification check procedure."""
        return [
            ATT_Write_Request(
                gatt_handle=self.__handle,
                data=bytes([0x01, 0x00])
            )
        ]

    def process_request(self, request: Packet) -> List[Packet]:
        """Process incoming PDUs."""

        # Do we got an error ? Force state to ERROR and save
        # the error details. Procedure is considered terminated.
        if ATT_Error_Response in request:
            self.set_result(request[ATT_Error_Response])
            self.set_state(Procedure.STATE_ERROR)
            return []

        # We are expecting a write response following our Initial
        # write into the target attribute (CCC descriptor)
        if self.get_state() == self.STATE_INITIAL:
            if ATT_Write_Response in request:
                # Write response received, update state
                self.set_state(self.STATE_SUB_DONE)
                return []

        # Once subed to a characteristic, we are expecting a notification
        # to complete this procedure.
        if self.get_state() == self.STATE_SUB_DONE:
            # If we received a notification, everything is fine
            # and procedure is done.
            if ATT_Handle_Value_Notification in request:
                self.set_result(request[ATT_Handle_Value_Notification])
                self.set_state(Procedure.STATE_DONE)
                return []

        # Default handler
        return []

