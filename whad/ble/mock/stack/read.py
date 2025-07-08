"""
# ATT Read procedure

The Read procedure is initiated by a Read request, and based on the required
attribute handle returns the attribute value (success) or an error (failure).
"""
from typing import List

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Hdr, ATT_Read_Request, ATT_Read_Response

from .attribute import find_attr_by_handle
from .procedure import Procedure

class ReadProcedure(Procedure):
    """ATT Read procedure."""

    def __init__(self, attributes: list):
        """Initialize our Read procedure."""
        super().__init__(attributes)

    @classmethod
    def trigger(cls, request):
        """Determine if the procedure is triggered."""
        return ATT_Read_Request in request

    def process_request(self, request) -> List[Packet]:
        """React only on ReadRequest."""
        request = request.getlayer(ATT_Read_Request)

        # We have a read request, look for the requested attribute
        try:
            # Query attributes
            attrib = find_attr_by_handle(self.attributes, request.gatt_handle)

            # Attribute is found, return a ReadResponse and mark procedure
            # as done
            self.set_state(Procedure.STATE_DONE)
            return [ATT_Hdr()/ATT_Read_Response(attrib.value)]
        except IndexError:
            self.set_state(Procedure.STATE_DONE)
            return [ATT_Hdr()/ATT_Error_Response(0x0A, request.handle, 0x01)]

