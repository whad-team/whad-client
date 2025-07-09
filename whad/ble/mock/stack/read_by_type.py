"""
ReadByType procedure

The ReadByType procedure is initiated by a ReadByType request, and
based on the required attribute start/end and type returns a
ReadByType response or an error.
"""
from struct import pack

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Read_By_Type_Request, ATT_Read_By_Type_Response

from whad.ble.profile.attribute import UUID

from .attribute import find_attr_by_type
from .procedure import Procedure, UnexpectedProcError

class ReadByTypeProcedure(Procedure):
    """ATT ReadByType procedure."""

    OPCODE = 0x08

    def __init__(self, attributes: list, mtu: int):
        """Initialize our ReadByType procedure.

        :param attributes: List of GATT attributes
        :type attributes: list
        :param mtu: ATT MTU
        :type mtu: int
        """
        super().__init__(attributes, mtu)

    @classmethod
    def trigger(cls, request: Packet) -> bool:
        """Determine if the procedure should be triggered.

        :param request: Packet to check
        :type request: scapy.packet.Packet
        :rtype: bool
        :return: `True` if this procedure must be triggered, `False` otherwise.
        """
        return ATT_Read_By_Type_Request in request

    def process_request(self, request: Packet) -> list[Packet]:
        """React only on a ReadByType request.

        :param request: Request packet to process
        :type request: scapy.packet.Packet
        :rtype: scapy.packet.Packet, list
        :return: a single packet or a list of packets
        """
        if ATT_Read_By_Type_Request not in request:
            self.set_state(Procedure.STATE_ERROR)
            raise UnexpectedProcError()

        # Extract ReadByType request
        request = request[ATT_Read_By_Type_Request]

        try:
            if request.start > request.end:
                self.set_state(Procedure.STATE_DONE)
                return self.att_error_response(request.handle, Procedure.ERR_INVALID_HANDLE)

            # List attributes by type
            attrs = find_attr_by_type(self.attributes, UUID(request.uuid),
                                      start_handle=request.start, end_handle=request.end)

            if len(attrs) == 0:
                self.set_state(Procedure.STATE_DONE)
                return self.att_error_response(request.start, Procedure.ERR_ATTR_NOT_FOUND)

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

            # Mark procedure as done
            self.set_state(Procedure.STATE_DONE)

            # Return attribute list
            return [ ATT_Read_By_Type_Response(len=attr_data_size, handles=resp) ]


        except IndexError:
            # Attribute cannot be found
            self.set_state(Procedure.STATE_DONE)
            return self.att_error_response(request.start, Procedure.ERR_ATTR_NOT_FOUND)
