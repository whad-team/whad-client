"""
ReadBlob procedure
"""
from typing import List

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Error_Response, ATT_Read_Blob_Request, ATT_Read_Blob_Response

from whad.ble.stack.att.constants import BleAttErrorCode, BleAttOpcode

from .attribute import find_attr_by_handle
from .procedure import BleClientProcedure, BleServerProcedure, UnexpectedProcError

class ServerReadBlobProcedure(BleServerProcedure):
    """ATT server ReadBlob procedure."""

    # ATT Operation code
    OPCODE = BleAttOpcode.READ_BLOB_REQUEST

    def __init__(self, attributes: list, mtu: int):
        """Initialize our ServerReadBlob procedure."""
        super().__init__(attributes, mtu)

    @classmethod
    def trigger(cls, request) -> bool:
        """Determine if the procedure is triggered."""
        return ATT_Read_Blob_Request in request

    def process_request(self, request: Packet) -> list[Packet]:
        """React only on ReadBlobRequest."""
        if ATT_Read_Blob_Request not in request:
            self.set_state(self.states.ERROR)
            raise UnexpectedProcError()

        request = request[ATT_Read_Blob_Request]

        try:
            # Query the requested attribute
            attr = find_attr_by_handle(self.attributes, request.gatt_handle)

            # Make sure we can read this attribute
            if not attr.readable():
                self.set_state(self.states.DONE)
                return self.att_error_response(request.gatt_handle, BleAttErrorCode.READ_NOT_PERMITTED)

            # Check offset
            if request.offset >= len(attr.value):
                self.set_state(self.states.DONE)
                return self.att_error_response(request.gatt_handle, BleAttErrorCode.INVALID_OFFSET)

            # Return value
            return [ ATT_Read_Blob_Response(value=attr.value[request.offset:self.mtu-1]) ]
        except IndexError:
            self.set_state(self.states.DONE)
            return self.att_error_response(request.gatt_handle, BleAttErrorCode.ATTRIBUTE_NOT_FOUND)

class ClientReadBlobProcedure(BleClientProcedure):
    """GATT Client ReadBlob Procedure."""

    # ATT Operation code
    OPCODE = BleAttOpcode.READ_BLOB_RESPONSE

    def __init__(self, handle: int, offset: int):
        """Initialize a ReadBlob procedure."""
        super().__init__([
            ATT_Read_Blob_Request(
                gatt_handle=handle,
                offset=offset
            )
        ])

    def process_request(self, request: Packet) -> List[Packet]:
        """Process incoming PDU."""
        if ATT_Error_Response in request:
            self.set_result(request[ATT_Error_Response])
            self.set_state(self.states.ERROR)
        elif ATT_Read_Blob_Response in request:
            response = request[ATT_Read_Blob_Response]
            self.set_result(response.value)
            self.set_state(self.states.DONE)
        else:
            self.set_result(None)
            self.set_state(self.states.ERROR)
        return []

