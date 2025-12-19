"""
FindInformation procedure

The ReadByType procedure is initiated by a ReadByType request, and
based on the required attribute start/end and type returns a
ReadByType response or an error.
"""
from typing import List
from struct import pack

from scapy.packet import Packet
from scapy.layers.bluetooth import (
    ATT_Error_Response, ATT_Find_Information_Request, ATT_Find_Information_Response,
    ATT_Find_By_Type_Value_Request, ATT_Find_By_Type_Value_Response
)

from whad.ble.profile.attribute import UUID
from whad.ble.stack.att.constants import BleAttErrorCode, BleAttOpcode

from .attribute import find_attr_by_range, find_attr_by_type
from .procedure import BleServerProcedure, BleClientProcedure, UnexpectedProcError

class ServerFindInformationProcedure(BleServerProcedure):
    """ATT FindInformation procedure."""

    # ATT Operation code
    OPCODE = BleAttOpcode.FIND_INFO_REQUEST

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
            self.set_state(self.states.ERROR)
            raise UnexpectedProcError()

        # Extract request
        request = request[ATT_Find_Information_Request]

        # List attributes with handles between start and end handles
        attrs = find_attr_by_range(self.attributes, start_handle=request.start, end_handle=request.end)
        if len(attrs) == 0:
            self.set_state(self.states.DONE)
            return self.att_error_response(request.start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND)

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
        self.set_state(self.states.DONE)
        return [
            ATT_Find_Information_Response(
                format=1 if attr_uuid_type == UUID.TYPE_16 else 2,
                handles=resp
            )
        ]

class ClientFindInformationProcedure(BleClientProcedure):
    """GATT Client FindInformation procedure."""

    # ATT Operation code
    OPCODE = BleAttOpcode.FIND_INFO_RESPONSE

    def __init__(self, start_handle: int, end_handle: int):
        """Initialize a FindInformation procedure.

        :param start_handle: Start handle
        :type start_handle: int
        :param end_handle: End handle
        :type end_handle: int
        """
        # Initialize our parent Procedure
        super().__init__([
            ATT_Find_Information_Request(
                start=start_handle,
                end=end_handle
            )
        ])

    def process_request(self, request: Packet) -> List[Packet]:
        """Process incoming packets, we expect to receive ATT_Error_Response or ATT_Find_Information_Response
        packets.

        :param packet: Received packet
        :type packet: scapy.packet.Packet
        :return: A list of packets to send in response to the received packets
        :rtype: list
        """
        # Did we receive an ATT error ?
        if ATT_Error_Response in request:
            self.set_result(request[ATT_Error_Response])
            self.set_state(self.states.ERROR)
            return []

        # Or did we receive an ATT_Find_Information_Response ?
        if ATT_Find_Information_Response in request:
            # Extract response
            response = request[ATT_Find_Information_Response]

            # Parse response content
            if response.format not in (1, 2):
                # Error, unknown format value
                self.set_result(None)
                self.set_state(self.states.ERROR)
                return []

            # Build list
            self.set_result(response.handles)
            self.set_state(self.states.DONE)
            return []
        else:
            self.set_result(None)
            self.set_state(self.states.ERROR)
            return []

class ServerFindByTypeValueProcedure(BleServerProcedure):
    """ATT FindInformation procedure."""

    # ATT Operation code
    OPCODE = BleAttOpcode.FIND_BY_TYPE_VALUE_REQUEST

    def __init__(self, attributes: list, mtu: int):
        """Initialize our ServerFindByTypeValue procedure."""
        super().__init__(attributes, mtu)

    @classmethod
    def trigger(cls, request) -> bool:
        """Determine if the procedure should be triggered."""
        return ATT_Find_By_Type_Value_Request in request

    def process_request(self, request: Packet) -> list[Packet]:
        """React only on a ATT_Find_Information_Request."""
        if ATT_Find_By_Type_Value_Request not in request:
            self.set_state(self.states.ERROR)
            raise UnexpectedProcError()

        # Extract request
        request = request[ATT_Find_By_Type_Value_Request]

        # List attributes with handles between start and end handles
        attrs = find_attr_by_type(self.attributes, UUID(request.uuid), start_handle=request.start, end_handle=request.end)
        if len(attrs) == 0:
            self.set_state(self.states.DONE)
            return self.att_error_response(request.start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND)

        # Build response
        resp = b""
        attr_uuid_type = None
        for attr in attrs:
            # If attribute value does not match, skip attribute.
            if attr.value != request.data:
                continue
            if attr_uuid_type is None:
                attr_uuid_type = attr.uuid.type
            if attr_uuid_type == attr.uuid.type:
                attr_data = pack("<HH", attr.handle, attr.end_handle)
                if self.mtu - 2 - len(resp) >= len(attr_data):
                    resp += attr_data
                else:
                    break
            else:
                break

        # If we did not find any service, return an error
        if resp == b'':
            self.set_state(self.states.DONE)
            return self.att_error_response(request.start, BleAttErrorCode.ATTRIBUTE_NOT_FOUND)

        # Send response
        self.set_state(self.states.DONE)
        return [
            ATT_Find_By_Type_Value_Response(
                handles=resp
            )
        ]

class ClientFindByTypeValueProcedure(BleClientProcedure):
    """GATT Client FindByTypeValue procedure."""

    def __init__(self, start_handle: int, end_handle: int, attr_type: UUID, attr_value: bytes):
        """Initialize a FindByTypeValue procedure.

        :param start_handle: Start handle
        :type start_handle: int
        :param end_handle: End handle
        :type end_handle: int
        :param attr_type: Attribute Type UUID
        :type attr_type: UUID
        :param attr_value: Attribute value
        :type attr_value: bytes
        """
        # Initialize our parent Procedure
        super().__init__([
            ATT_Find_By_Type_Value_Request(
                start=start_handle,
                end=end_handle,
                uuid=attr_type.value(),
                data=attr_value
            )
        ])

    def process_request(self, request: Packet) -> List[Packet]:
        """Process incoming packets, we expect to receive ATT_Error_Response or ATT_Find_Information_Response
        packets.

        :param packet: Received packet
        :type packet: scapy.packet.Packet
        :return: A list of packets to send in response to the received packets
        :rtype: list
        """
        # Did we receive an ATT error ?
        if ATT_Error_Response in request:
            self.set_result(request[ATT_Error_Response])
            self.set_state(self.states.ERROR)
            return []

        # Or did we receive an ATT_Find_Information_Response ?
        if ATT_Find_By_Type_Value_Response in request:
            # Extract response
            response = request[ATT_Find_By_Type_Value_Response]
            self.set_result(response)
            self.set_state(self.states.DONE)
            return []
        else:
            self.set_result(None)
            self.set_state(self.states.ERROR)
            return []

