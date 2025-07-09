"""
Write procedure
"""
from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Write_Request, ATT_Write_Response

from .attribute import find_attr_by_handle
from .procedure import Procedure, UnexpectedProcError

class WriteProcedure(Procedure):
    """ATT Write procedure."""

    OPCODE = 0x12

    def __init__(self, attributes: list, mtu: int):
        """Initialize our Write procedure."""
        super().__init__(attributes, mtu)

    @classmethod
    def trigger(cls, request) -> bool:
        """Determine if the procedure is triggered."""
        return ATT_Write_Request in request

    def process_request(self, request: Packet) -> list[Packet]:
        """React only on WriteRequest."""
        if ATT_Write_Request not in request:
            self.set_state(Procedure.STATE_ERROR)
            raise UnexpectedProcError()

        request = request[ATT_Write_Request]

        # Search for the requested attribute
        try:
            attr = find_attr_by_handle(self.attributes, request.gatt_handle)

            # Check we are attempting to modify a characteristic value or a CCCD
            if attr.writeable():
                attr.value = request.data
                self.set_state(Procedure.STATE_DONE)
                return [ ATT_Write_Response() ]
            else:
                self.set_state(Procedure.STATE_DONE)
                return self.att_error_response(request.gatt_handle, Procedure.ERR_WRITE_NOT_PERMITTED)
        except IndexError:
            self.set_state(Procedure.STATE_DONE)
            return self.att_error_response(request.gatt_handle, Procedure.ERR_ATTR_NOT_FOUND)

