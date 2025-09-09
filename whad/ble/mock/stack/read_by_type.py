"""
ReadByType procedure

The ReadByType procedure is initiated by a ReadByType request, and
based on the required attribute start/end and type returns a
ReadByType response or an error.
"""
from typing import List
from struct import pack

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Error_Response, ATT_Read_By_Type_Request, ATT_Read_By_Type_Response

from whad.ble.profile.attribute import UUID
from whad.ble.stack.att.constants import BleAttErrorCode, BleAttOpcode

from .attribute import find_attr_by_type
from .procedure import BleClientProcedure, BleServerProcedure, UnexpectedProcError

class ServerReadByTypeProcedure(BleServerProcedure):
    """ATT server ReadByType procedure for GATT server."""

    OPCODE = BleAttOpcode.READ_BY_TYPE_REQUEST

    def __init__(self, attributes: list, mtu: int):
        """Initialize our ServerReadByType procedure.

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

    def process_request(self, request: Packet) -> List[Packet]:
        """React only on a ReadByType request.

        :param request: Request packet to process
        :type request: scapy.packet.Packet
        :rtype: scapy.packet.Packet, list
        :return: a single packet or a list of packets
        """
        if ATT_Read_By_Type_Request not in request:
            self.set_state(self.states.ERROR)
            raise UnexpectedProcError()

        # Extract ReadByType request
        request = request[ATT_Read_By_Type_Request]

        try:
            if request.start > request.end:
                self.set_state(self.states.DONE)
                return self.att_error_response(request.handle, BleAttErrorCode.INVALID_HANDLE)

            # List attributes by type
            attrs = find_attr_by_type(self.attributes, UUID(request.uuid),
                                      start_handle=request.start, end_handle=request.end)

            if len(attrs) == 0:
                self.set_state(self.states.DONE)
                return self.att_error_response(request.start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND)

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
            self.set_state(self.states.DONE)

            # Return attribute list
            return [ ATT_Read_By_Type_Response(len=attr_data_size, handles=resp) ]


        except IndexError:
            # Attribute cannot be found
            self.set_state(self.states.DONE)
            return self.att_error_response(request.start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND)

class ClientReadByTypeProcedure(BleClientProcedure):
    """ Client ReadByType procedure. """

    OPCODE = BleAttOpcode.READ_BY_TYPE_RESPONSE

    def __init__(self, start_handle: int, end_handle: int, type_uuid: UUID):
        """Initialize a client ReadByType procedure.

        :param start_handle: Start handle
        :type start_handle: int
        :param end_handle: End handle
        :type end_handle: int
        :param type_uuid: Attribute type UUID
        :type type_uuid: UUID
        """
        # Initialize parent procedure
        super().__init__([
            ATT_Read_By_Type_Request(
                start=start_handle,
                end=end_handle,
                uuid=type_uuid.value()
            )
        ])

    def process_request(self, request: Packet) -> List[Packet]:
        """Process incoming packet.

        :param request: Received packet
        :type request: Packet
        :return: List of packets to send in response
        :rtype: list
        """
        if ATT_Error_Response in request:
            self.set_result(request[ATT_Error_Response])
            self.set_state(self.states.ERROR)
        elif ATT_Read_By_Type_Response in request:
            # Save response as result
            self.set_result(request[ATT_Read_By_Type_Response])
            self.set_state(self.states.DONE)
        else:
            # Other packets: fail
            self.set_result(None)
            self.set_state(self.states.ERROR)

        # No other packets to send
        return []

