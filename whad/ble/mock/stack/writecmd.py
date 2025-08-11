"""
Write command procedure
"""
from typing import List, Optional, Any
from time import sleep

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Write_Command, ATT_Error_Response

from .attribute import CharacteristicValue, find_attr_by_handle
from .procedure import Procedure, UnexpectedProcError

class ServerWriteCommandProcedure(Procedure):
    """ATT server WriteCommand procedure."""

    OPCODE = 0x52

    def __init__(self, attributes: list, mtu: int):
        """Initialize our ServerWriteCommand procedure."""
        super().__init__(attributes, mtu)

    @classmethod
    def trigger(cls, request) -> bool:
        """Determine if the procedure is triggered."""
        return ATT_Write_Command in request

    def process_request(self, request: Packet) -> list[Packet]:
        """React only on WriteRequest."""
        if ATT_Write_Command not in request:
            self.set_state(Procedure.STATE_ERROR)
            raise UnexpectedProcError()

        request = request[ATT_Write_Command]

        try:
            # Find attribute
            attr = find_attr_by_handle(self.attributes,request.gatt_handle)

            # Write into attribute's value if allowed to
            if isinstance(attr, CharacteristicValue) and attr.writeable_without_resp():
                attr.value = request.data

        except IndexError:
            pass

        # We don't send anything in return
        self.set_state(Procedure.STATE_DONE)
        return []

class ClientWriteCommandProcedure(Procedure):
    """GATT Client WriteCommand procedure"""

    def __init__(self, handle: int, value: bytes):
        """Initialize a client WriteCommand procedure."""
        self.__handle = handle
        self.__value = value
        super().__init__([], 23)


    def initiate(self) -> List[Packet]:
        """Initiate WriteCommand procedure."""
        self.set_result(None)
        return [
            ATT_Write_Command(
                gatt_handle=self.__handle,
                data=self.__value
            )
        ]

    def wait(self, timeout: Optional[float] = None) -> Optional[Any]:
        sleep(.3)
        if self.get_state() == Procedure.STATE_INITIAL:
            self.set_result(None)
            self.set_state(Procedure.STATE_DONE)
        return super().wait(timeout=timeout)

    def process_request(self, request: Packet) -> List[Packet]:
        """Process incoming PDUs."""
        if ATT_Error_Response in request:
            self.set_result(request[ATT_Error_Response])
            self.set_state(Procedure.STATE_ERROR)
        return []

