"""
FindInformation procedure

The ReadByType procedure is initiated by a ReadByType request, and
based on the required attribute start/end and type returns a
ReadByType response or an error.
"""
from struct import pack

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Find_Information_Request, ATT_Find_Information_Response

from whad.ble.profile.attribute import UUID

from .attribute import find_attr_by_range
from .procedure import Procedure, UnexpectedProcError

class ServerFindInformationProcedure(Procedure):
    """ATT FindInformation procedure."""

    OPCODE = 0x04

    def __init__(self, attributes: list, mtu: int):
        """Initialize our ServerFindInformation procedure."""
        super().__init__(attributes, mtu)

    @classmethod
    def trigger(cls, request) -> bool:
        """Determine if the procedure should be triggered."""
        return ATT_Find_Information_Request in request

    def process_request(self, request: Packet) -> list[Packet]:
        """React only on a ATT_Find_Information_Request."""
        if ATT_Find_Information_Request not in request:
            self.set_state(Procedure.STATE_ERROR)
            raise UnexpectedProcError()

        # Extract request
        request = request[ATT_Find_Information_Request]

        # List attributes with handles between start and end handles
        attrs = find_attr_by_range(self.attributes, start_handle=request.start, end_handle=request.end)
        if len(attrs) == 0:
            self.set_state(Procedure.STATE_DONE)
            return self.att_error_response(request.start, Procedure.ERR_ATTR_NOT_FOUND)

        # Build response
        resp = b""
        attr_uuid_type = None
        for attr in attrs:
            if attr_uuid_type is None:
                attr_uuid_type = attr.uuid.type
            if attr_uuid_type == attr.uuid.type:
                attr_data = pack("<H", attr.handle) + attr.uuid.packed
                if self.mtu - 2 - len(resp) >= len(attr_data):
                    resp += attr_data
                else:
                    break
            else:
                break

        # Send response
        self.set_state(Procedure.STATE_DONE)
        return [
            ATT_Find_Information_Response(
                format=1 if attr_uuid_type == UUID.TYPE_16 else 2,
                handles=resp
            )
        ]

