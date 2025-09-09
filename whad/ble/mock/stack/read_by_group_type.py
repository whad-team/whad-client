"""
ReadByGroupType procedure

The ReadByGroupType procedure is initiated by a ReadByGroupType request, and
based on the required attribute start/end handle and group type returns a
ReadByGroupType response or an error.
"""
from typing import List
from struct import pack

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Error_Response, ATT_Read_By_Group_Type_Request, ATT_Read_By_Group_Type_Response

from whad.ble.profile.attribute import UUID
from whad.ble.stack.att.constants import BleAttErrorCode, BleAttOpcode
from whad.ble.stack.gatt.attrlist import GattAttributeDataList, GattGroupTypeItem

from .attribute import find_attr_by_type
from .procedure import BleClientProcedure, BleServerProcedure, UnexpectedProcError

class ServerReadByGroupTypeProcedure(BleServerProcedure):
    """ATT server ReadByGroupType procedure."""

    # Procedure operation code
    OPCODE = BleAttOpcode.READ_BY_GROUP_TYPE_REQUEST

    def __init__(self, attributes: list, mtu: int):
        """Initialize our ServerReadByGroupType procedure."""
        super().__init__(attributes, mtu)

    @classmethod
    def trigger(cls, request) -> bool:
        """Determine if the procedure is triggered."""
        return ATT_Read_By_Group_Type_Request in request

    def process_request(self, request: Packet) -> list[Packet]:
        """React only on a ReadByGroupType request."""
        # We should not be called when request does not contain a ReadByGroupType request.
        if ATT_Read_By_Group_Type_Request not in request:
            self.set_state(self.states.ERROR)
            raise UnexpectedProcError()

        # Extract ReadByGroupType request
        request = request[ATT_Read_By_Group_Type_Request]

        try:
            # Make sure start handle is valid
            if request.start > request.end:
                self.set_state(self.states.DONE)
                return self.att_error_response(handle=request.start, ecode=BleAttErrorCode.INVALID_HANDLE)

            # List attributes corresponding to the provided group type, return an error
            # if no attribute is found.
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

            # Mark procedure as done
            self.set_state(self.states.DONE)

            # Return attribute list
            return [ ATT_Read_By_Group_Type_Response(
                    length=attr_data_size,
                    data=resp
                )
            ]

        except IndexError:
            self.set_state(self.states.DONE)
            return self.att_error_response(request.start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND)

class ClientReadByGroupTypeProcedure(BleClientProcedure):
    """ATT client ReadByGroupType procedure."""

    # Procedure operation code
    OPCODE = BleAttOpcode.READ_BY_GROUP_TYPE_RESPONSE

    def __init__(self, group_type: UUID, start: int, end: int):
        """Initialize our ClientReadByGroupType procedure."""

        # Save requested parameters
        self.__uuid = group_type.value()
        self.__start = start
        self.__end = end

        # Initialize our procedure object, no attributes required
        # as we don't expose any attribute.
        super().__init__([
            ATT_Read_By_Group_Type_Request(
                uuid=self.__uuid,
                start=self.__start,
                end=self.__end
            )
        ])

    @classmethod
    def trigger(cls, request) -> bool:
        """Determine if the procedure is triggered."""
        return ATT_Read_By_Group_Type_Response in request

    def process_request(self, request: Packet) -> List[Packet]:
        """React only on a ReadByGroupType response."""
        # Do we received an ATT Error message ?
        if ATT_Error_Response in request:
            self.set_state(self.states.ERROR)
            self.set_result(request[ATT_Error_Response])
            return []

        # We should not be called when request does not contain a ReadByGroupType request.
        if ATT_Read_By_Group_Type_Response not in request:
            self.set_state(self.states.ERROR)
            raise UnexpectedProcError()

        # Extract ReadByGroupType response
        request = request[ATT_Read_By_Group_Type_Response]

        if request.length > 0:
            # Parse response
            items = GattAttributeDataList.from_bytes(
                request.data,
                request.length,
                GattGroupTypeItem
            )
            self.set_result(items)
            self.set_state(self.states.DONE)
        else:
            self.set_result(None)
            self.set_state(self.states.ERROR)

        # No packet to send.
        return []
