"""
Bluetooth Low Energy Tiny Stack for Unit Testing
================================================

GATT client has no profile but implements a basic
discovery procedure that will populate its internal
attribute database.
"""

import logging
from typing import List

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Hdr

from whad.ble.profile.attribute import UUID

from .attribute import Attribute

# ATT Procedures
from .procedure import UnexpectedProcError
from .read_by_group_type import ClientReadByGroupTypeProcedure
from .read_by_type import ClientReadByTypeProcedure
from .readblob import ClientReadBlobProcedure
from .read import ClientReadProcedure
from .write import ClientWriteProcedure
from .writecmd import ClientWriteCommandProcedure
from .find_info import ClientFindInformationProcedure, ClientFindByTypeValueProcedure
from .notif import ClientNotificationCheckProcedure, ClientIndicationCheckProcedure

logger = logging.getLogger(__name__)

class GattClient:
    """Tiny GATT client"""

    def __init__(self, l2cap: 'Llcap' = None):
        """Initialize a GATT client."""

        self.__l2cap = l2cap

        # Initialize client state
        self.__attributes = []
        self.__mtu = 23
        self.__cur_procedure = None

        # Register procedures
        self.__procedures = [
            ClientReadByGroupTypeProcedure,
            ClientReadByTypeProcedure,
            ClientReadProcedure,
            ClientReadBlobProcedure,
            ClientWriteProcedure,
            ClientWriteCommandProcedure,
            ClientFindInformationProcedure,
            ClientFindByTypeValueProcedure,
            ClientNotificationCheckProcedure,
            ClientIndicationCheckProcedure,
        ]

    @property
    def attributes(self) -> List[Attribute]:
        """Remote server attributes."""
        return self.__attributes

    def set_l2cap(self, obj):
        """Set L2CAP layer for this GattClient."""
        self.__l2cap = obj

    def on_pdu(self, request: Packet) -> List[Packet]:
        """Process incoming response/error."""
        # If a suitable procedure has been found or is in progress, forward request.
        if self.__cur_procedure is not None:
            # Forward to current procedure
            answers: list[Packet] = self.__cur_procedure.process_request(request)

            # Unset current procedure if finished
            if self.__cur_procedure.done():
                #self.__cur_procedure = None
                """nope"""

            # Automatically add ATT_Hdr()
            if isinstance(answers, list):
                return [ ATT_Hdr()/ans if ATT_Hdr not in ans else ans for ans in answers]
            else:
                # Should not happen so raise an exception
                raise UnexpectedProcError()
        else:
            logger.warning("[ble::mock::stack::gatt_client] No procedure to handle packet ! (%s)", request)
            return []

    def read_by_group_type(self, group_type: UUID, start_handle: int, end_handle: int) -> List[Packet]:
        """Enumerate attributes by group type."""
        # Initiate a ClientReadByGroupTypeProcedure
        self.__cur_procedure = ClientReadByGroupTypeProcedure(
            group_type, start_handle,end_handle
        )

        # Generate ATT packets to send when this procedure is initiated
        # and forward them to the underlying link-layer
        for req in self.__cur_procedure.initiate():
            self.__l2cap.send_pdu(ATT_Hdr()/req)


    def read_by_type(self, start_handle: int, end_handle: int, type_uuid: UUID) -> List[Packet]:
        """Read attributes by type."""
        # Initiate a ClientReadByTypeProcedure
        self.__cur_procedure = ClientReadByTypeProcedure(
            start_handle, end_handle, type_uuid
        )

        # Generate ATT packets to send when this procedure is initiated
        # and forward them to the underlying link-layer
        for req in self.__cur_procedure.initiate():
            self.__l2cap.send_pdu(ATT_Hdr()/req)

    def read(self, handle: int) -> List[Packet]:
        """Read attribute."""
        # Initiate a ClientReadProcedure
        self.__cur_procedure = ClientReadProcedure(handle)

        # Generate ATT packets to send when this procedure is initiated
        # and forward them to the underlying link-layer
        for req in self.__cur_procedure.initiate():
            self.__l2cap.send_pdu(ATT_Hdr()/req)

    def read_blob(self, handle: int, offset: int) -> List[Packet]:
        """Read part of attribute."""
        # Initiate a ClientReadBlobProcedure
        self.__cur_procedure = ClientReadBlobProcedure(handle, offset)

        # Generate ATT packets to send when this procedure is initiated
        # and forward them to the underlying link-layer
        for req in self.__cur_procedure.initiate():
            self.__l2cap.send_pdu(ATT_Hdr()/req)

    def find_information(self, start_handle: int, end_handle: int):
        """Find information (attribute type) about a list of handles.

        :param start_handle: Start handle
        :type start_handle: int
        :param end_handle: End handle, must be lower or equal to start handle
        :type end_handle: int
        :return: List of packets to send once the procedure initiated
        :rtype: list
        """
        # Initiate a ClientFindInformationProcedure
        self.__cur_procedure = ClientFindInformationProcedure(start_handle, end_handle)

        # Generate ATT packets to send when this procedure is initiated and forward
        # them to the underlying L2CAP layer.
        for req in self.__cur_procedure.initiate():
            self.__l2cap.send_pdu(ATT_Hdr()/req)

    def find_by_type_value(self, start_handle: int, end_handle: int, attr_type: UUID, attr_value: bytes):
        """Find attribute by type UUID.

        :param start_handle: Start handle
        :type start_handle: int
        :param end_handle: End handle, must be lower or equal to start handle
        :type end_handle: int
        :param attr_type: Attribute Type UUID
        :type attr_type: UUID
        :return: List of packets to send once the procedure initiated
        :rtype: list
        """
        # Initiate a ClientFindInformationProcedure
        self.__cur_procedure = ClientFindByTypeValueProcedure(start_handle, end_handle, attr_type, attr_value)

        # Generate ATT packets to send when this procedure is initiated and forward
        # them to the underlying L2CAP layer.
        for req in self.__cur_procedure.initiate():
            self.__l2cap.send_pdu(ATT_Hdr()/req)


    def wait_procedure(self, timeout: float = None):
        """Wait for the current procedure to complete."""
        return self.__cur_procedure.wait(timeout=timeout)

    def write(self, handle: int, value: bytes) -> List[Packet]:
        """Write value into a specified attribute."""
        # Initiate a ClientWriteProcedure
        self.__cur_procedure = ClientWriteProcedure(handle, value)

        # Generate ATT packets to send when this procedure is initiated
        # and forward them to the underlying link-layer
        for req in self.__cur_procedure.initiate():
            self.__l2cap.send_pdu(ATT_Hdr()/req)

    def write_cmd(self, handle: int, value: bytes) -> List[Packet]:
        """Write value into a specific attribute without waiting
        for a response.

        :param handle: Handle of the target attribute
        :type handle: int
        :param value: Value to write into the target attribute
        :type value: bytes
        """
        # Initiate a ClientWriteCommandProcedure
        self.__cur_procedure = ClientWriteCommandProcedure(handle, value)

        # Generate ATT packets to send when this procedure is initiated
        # and forward them to the underlying link-layer
        for req in self.__cur_procedure.initiate():
            self.__l2cap.send_pdu(ATT_Hdr()/req)

    def sub_notif(self, handle: int):
        """Subscribe to notification for the specified handler."""
        # Initiate a ClientNotificationCheckProcedure
        self.__cur_procedure = ClientNotificationCheckProcedure(handle)

        # Generate ATT packets to send when this procedure is initiated
        # and forward them to the underlying link-layer
        for req in self.__cur_procedure.initiate():
            self.__l2cap.send_pdu(ATT_Hdr()/req)

    def sub_ind(self, handle: int):
        """Subscribe to notification for the specified handler."""
        # Initiate a ClientNotificationCheckProcedure
        self.__cur_procedure = ClientIndicationCheckProcedure(handle)

        # Generate ATT packets to send when this procedure is initiated
        # and forward them to the underlying link-layer
        for req in self.__cur_procedure.initiate():
            self.__l2cap.send_pdu(ATT_Hdr()/req)

