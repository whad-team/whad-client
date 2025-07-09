"""
ReadByGroupType procedure

The ReadByGroupType procedure is initiated by a ReadByGroupType request, and
based on the required attribute start/end handle and group type returns a
ReadByGroupType response or an error.
"""
from struct import pack

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Read_By_Group_Type_Request, ATT_Error_Response,\
    ATT_Read_By_Group_Type_Response, ATT_Hdr

from whad.ble.profile.attribute import UUID

from .attribute import find_attr_by_type
from .procedure import Procedure

class ReadByGroupTypeProcedure(Procedure):
    """ATT ReadByGroupType procedure."""

    def __init__(self, attributes: list, mtu: int):
        """Initialize our ReadByGroupType procedure."""
        super().__init__(attributes, mtu)

    @classmethod
    def trigger(cls, request) -> bool:
        """Determine if the procedure is triggered."""
        return ATT_Read_By_Group_Type_Request in request

    def process_request(self, request: Packet) -> list[Packet]:
        """React only on a ReadByGroupType request."""
        request = request.getlayer(ATT_Read_By_Group_Type_Request)

        try:
            # Make sure start handle is valid
            if request.start > request.end:
                self.set_state(Procedure.STATE_DONE)
                return [ATT_Error_Response(request=0x10, handle=request.start, ecode=0x01)]

            # List attributes corresponding to the provided group type, return an error
            # if no attribute is found.
            attrs = find_attr_by_type(self.attributes, UUID(request.uuid),
                                      start_handle=request.start, end_handle=request.end)
            if len(attrs) == 0:
                self.set_state(Procedure.STATE_DONE)
                return [ATT_Hdr()/ATT_Error_Response(request=0x10, handle=request.start, ecode=0x0A)]

            # Build response value
            resp = b""
            attr_data_size = None
            for attr in attrs:
                # Append attribute info to our response
                attr_data = pack("<HH", attr.handle, attr.end_handle) + attr.value

                # Save attribute data size if not set
                if attr_data_size is None:
                    attr_data_size = len(attr_data)

                # Append data if same size and not exceeding mtu
                if len(attr_data) == attr_data_size:
                    if self.mtu - len(resp) - 2 >= attr_data_size:
                        resp += attr_data
                    else:
                        break
                else:
                    break

            # Return attribute list
            result = ATT_Read_By_Group_Type_Response(
                    length=attr_data_size,
                    data=resp
                )

            # Mark procedure as done
            self.set_state(Procedure.STATE_DONE)
            return [ATT_Hdr()/result]

        except IndexError:
            self.set_state(Procedure.STATE_DONE)
            return [
                ATT_Hdr()/ATT_Error_Response(request=0x10, handle=request.start, ecode=0x01)
            ]

