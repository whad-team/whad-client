"""
Write command procedure
"""
from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Write_Command

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

