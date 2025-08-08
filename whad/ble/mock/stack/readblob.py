"""
ReadBlob procedure
"""
from typing import List

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Error_Response, ATT_Read_Blob_Request, ATT_Read_Blob_Response

from .attribute import find_attr_by_handle
from .procedure import Procedure, UnexpectedProcError

class ServerReadBlobProcedure(Procedure):
    """ATT server ReadBlob procedure."""

    OPCODE = 0x0C

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
            self.set_state(Procedure.STATE_ERROR)
            raise UnexpectedProcError()

        request = request[ATT_Read_Blob_Request]

        try:
            # Query the requested attribute
            attr = find_attr_by_handle(self.attributes, request.gatt_handle)

            # Make sure we can read this attribute
            if not attr.readable():
                self.set_state(Procedure.STATE_DONE)
                return self.att_error_response(request.gatt_handle, Procedure.ERR_READ_NOT_PERMITTED)

            # Check offset
            if request.offset >= len(attr.value):
                self.set_state(Procedure.STATE_DONE)
                return self.att_error_response(request.gatt_handle, Procedure.ERR_INVALID_OFFSET)

            # Return value
            return [ ATT_Read_Blob_Response(value=attr.value[request.offset:self.mtu-1]) ]
        except IndexError:
            self.set_state(Procedure.STATE_DONE)
            return self.att_error_response(request.gatt_handle, Procedure.ERR_ATTR_NOT_FOUND)

class ClientReadBlobProcedure(Procedure):
    """GATT Client ReadBlob Procedure."""

    def __init__(self, handle: int, offset: int):
        """Initialize a ReadBlob procedure."""
        self.__handle = handle
        self.__offset = offset
        super().__init__([], 23)

    def initiate(self) -> List[Packet]:
        """Initiate a ReadBlob procedure."""
        return [
            ATT_Read_Blob_Request(
                gatt_handle=self.__handle,
                offset=self.__offset
            )
        ]

    def process_request(self, request: Packet) -> List[Packet]:
        """Process incoming PDU."""
        if ATT_Error_Response in request:
            self.set_result(request[ATT_Error_Response])
            self.set_state(Procedure.STATE_ERROR)
        elif ATT_Read_Blob_Response in request:
            response = request[ATT_Read_Blob_Response]
            self.set_result(response.value)
            self.set_state(Procedure.STATE_DONE)
        else:
            self.set_result(None)
            self.set_state(Procedure.STATE_ERROR)
        return []

