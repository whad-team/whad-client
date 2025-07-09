"""
# ATT Read procedure

The Read procedure is initiated by a Read request, and based on the required
attribute handle returns the attribute value (success) or an error (failure).
"""
from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Read_Request, ATT_Read_Response

from .attribute import find_attr_by_handle
from .procedure import Procedure, UnexpectedProcError

class ReadProcedure(Procedure):
    """ATT Read procedure."""

    # Read operation code
    OPCODE = 0x0A

    def __init__(self, attributes: list, mtu: int):
        """Initialize our Read procedure."""
        super().__init__(attributes, mtu)

    @classmethod
    def trigger(cls, request) -> bool:
        """Determine if the procedure is triggered."""
        return ATT_Read_Request in request

    def process_request(self, request) -> list[Packet]:
        """React only on ReadRequest."""

        # Sanity check
        if ATT_Read_Request not in request:
            self.set_state(Procedure.STATE_ERROR)
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
                self.set_state(Procedure.STATE_DONE)
                return [ ATT_Read_Response(value=attrib.value[:self.mtu]) ]
            else:
                # Read not allowed
                self.set_state(Procedure.STATE_DONE)
                return self.att_error_response(request.gatt_handle, Procedure.ERR_READ_NOT_PERMITTED)
        except IndexError:
            self.set_state(Procedure.STATE_DONE)
            return self.att_error_response(request.gatt_handle, Procedure.ERR_ATTR_NOT_FOUND)

