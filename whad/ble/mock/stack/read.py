"""
# ATT Read procedure

The Read procedure is initiated by a Read request, and based on the required
attribute handle returns the attribute value (success) or an error (failure).
"""
from typing import List

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Error_Response, ATT_Read_Request, ATT_Read_Response

from whad.ble.stack.att.constants import BleAttErrorCode, BleAttOpcode

from .attribute import find_attr_by_handle
from .procedure import UnexpectedProcError, BleClientProcedure, BleServerProcedure

class ServerReadProcedure(BleServerProcedure):
    """ATT server Read procedure."""

    # Read operation code
    OPCODE = BleAttOpcode.READ_REQUEST

    def __init__(self, attributes: list, mtu: int):
        """Initialize our server Read procedure."""
        super().__init__( attributes, mtu)

    @classmethod
    def trigger(cls, request) -> bool:
        """Determine if the procedure is triggered."""
        return ATT_Read_Request in request

    def process_request(self, request) -> list[Packet]:
        """React only on ReadRequest."""

        # Sanity check
        if ATT_Read_Request not in request:
            self.set_state(self.states.ERROR)
            raise UnexpectedProcError()

        # Extract Read request
        request = request[ATT_Read_Request]

        # We have a read request, look for the requested attribute
        try:
            # Query attributes
            attrib = find_attr_by_handle(self.attributes, request.gatt_handle)

            # Make sure attribute can be read
            if attrib.readable():
                # Attribute is found, return a ReadResponse and mark procedure
                # as done.
                self.set_state(self.states.DONE)
                return [ ATT_Read_Response(value=attrib.value[:self.mtu]) ]
            else:
                # Read not allowed
                self.set_state(self.states.DONE)
                return self.att_error_response(request.gatt_handle, BleAttErrorCode.READ_NOT_PERMITTED)
        except IndexError:
            self.set_state(self.states.DONE)
            return self.att_error_response(request.gatt_handle, BleAttErrorCode.ATTRIBUTE_NOT_FOUND)

class ClientReadProcedure(BleClientProcedure):
    """GATT Client Read procedure."""

    OPCODE = BleAttOpcode.READ_RESPONSE

    def __init__(self, handle: int):
        """Initialize a GATT client Read procedure.

        :param handle: Handle of attribute to read
        :type handle: int
        """
        self.__handle = handle
        super().__init__([
            ATT_Read_Request(gatt_handle=self.__handle)
        ])

    def process_request(self, request: Packet) -> List[Packet]:
        """Process incoming packet."""
        if ATT_Error_Response in request:
            self.set_result(request[ATT_Error_Response])
            self.set_state(self.states.ERROR)
        elif ATT_Read_Response in request:
            response = request[ATT_Read_Response]
            self.set_result(response.value)
            self.set_state(self.states.DONE)
        return []

