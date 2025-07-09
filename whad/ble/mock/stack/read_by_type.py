"""
ReadByType procedure

The ReadByType procedure is initiated by a ReadByType request, and
based on the required attribute start/end and type returns a
ReadByType response or an error.
"""

from struct import pack

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Read_By_Type_Request, ATT_Error_Response,\
    ATT_Read_By_Type_Response, ATT_Hdr

from whad.ble.profile.attribute import UUID

from .attribute import find_attr_by_type
from .procedure import Procedure

class ReadByTypeProcedure(Procedure):
    """ATT ReadByType procedure."""

    def __init__(self, attributes: list, mtu: int):
        """Initialize our ReadByType procedure."""
        super().__init__(attributes, mtu)

    @classmethod
    def trigger(cls, request) -> bool:
        """Determine if the procedure should be triggered."""
        return ATT_Read_By_Type_Request in request

    def process_request(self, request: Packet) -> list[Packet]:
        """React only on a ReadByType request."""
        request = request.getlayer(ATT_Read_By_Type_Request)

        try:
            if request.start > request.end:
                self.set_state(Procedure.STATE_DONE)
                return [ATT_Hdr()/ATT_Error_Response(request=0x08,handle=request.handle,ecode=0x01)]

            # List attributes by type
            attrs = find_attr_by_type(self.attributes, UUID(request.uuid), start_handle=request.start, end_handle=request.end)

            if len(attrs) == 0:
                self.set_state(Procedure.STATE_DONE)
                return [ATT_Hdr()/ATT_Error_Response(request=0x08, handle=request.start, ecode=0x0A)]

            # Build response value
            resp = b""
            attr_data_size = None
            for attr in attrs:
                # Append attribute info to our response
                attr_data = pack("<H", attr.handle) + attr.value

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
            result = ATT_Read_By_Type_Response(
                    len=attr_data_size,
                    handles=resp
                )

            # Mark procedure as done
            self.set_state(Procedure.STATE_DONE)
            return [ATT_Hdr()/result]

        except IndexError:
            return [
                ATT_Hdr()/ATT_Error_Response(
                    request=0x08,
                    handle=request.start,
                    ecode=0x01
                )
            ]
