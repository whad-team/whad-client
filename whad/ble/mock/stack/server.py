"""
Bluetooth Low Energy Tiny Stack for Unit Testing
================================================

GATT server profile:

- Generic Access Service (0x1800)
  - DeviceName (0x2A00), read/write permissions
- Battery Service (0x180F)
  - Battery Level (0x2A19), read/notify/indicate permissions
- Custom Service (6d02b600-1b51-4ef9-b753-1399e05debfd)
  - TX characteristic (6d02b601-1b51-4ef9-b753-1399e05debfd): writecmd
  - RX characteristic (6d02b602-1b51-4ef9-b753-1399e05debfd): read/notify permissions
"""
from typing import List
from struct import pack

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Hdr, ATT_Error_Response

from whad.ble.profile.attribute import UUID

from .attribute import Attribute, PrimaryService, Characteristic, CharacteristicValue, \
    ClientCharacteristicConfigurationDescriptor

# ATT Procedures
from .read import ReadProcedure
from .read_by_group_type import ReadByGroupTypeProcedure
from .read_by_type import ReadByTypeProcedure
from .find_info import FindInformationProcedure

class GattServer:
    """Tiny GATT server"""

    def __init__(self):
        """Initialize a GATT server."""
        ###
        # Initialize GATT attributes
        ###

        self.__attributes = [
            # Primary Service, Generic Access Service (0x1800), handle 1-3
            PrimaryService(1, 3,UUID(0x1800)),
            Characteristic(2, UUID(0x2A00), value_handle=3, properties=(
                Characteristic.PROP_READ | Characteristic.PROP_WRITE
            )),
            CharacteristicValue(3, UUID(0x2A00), b"EmulatedDevice"),

            # Primary Service, Battery Level Service (0x180F), handle 4-7
            PrimaryService(4, 7, UUID(0x180F)),
            Characteristic(5, UUID(0x2A19), value_handle=6, properties=(
                Characteristic.PROP_READ | Characteristic.PROP_NOTIFY | Characteristic.PROP_INDICATE
            )),
            CharacteristicValue(6, UUID(0x2A19), pack("<H", 0)),
            ClientCharacteristicConfigurationDescriptor(7),

            # Primary Service, custom service (6d02b602-1b51-4ef9-b753-1399e05debfd), handle 7-10
            PrimaryService(8, 13, UUID("6d02b600-1b51-4ef9-b753-1399e05debfd")),

            # TX Characteristic
            Characteristic(9, UUID("6d02b601-1b51-4ef9-b753-1399e05debfd"), value_handle=10, properties=(
                Characteristic.PROP_WRITE_WITHOUT_RESP
            )),
            CharacteristicValue(10, UUID("6d02b601-1b51-4ef9-b753-1399e05debfd"), b"\x00\x00\x00\x00"),

            # RX Characteristic
            Characteristic(11, UUID("6d02b602-1b51-4ef9-b753-1399e05debfd"), value_handle=12, properties=(
                Characteristic.PROP_READ | Characteristic.PROP_NOTIFY
            )),
            CharacteristicValue(12, UUID("6d02b602-1b51-4ef9-b753-1399e05debfd"), b"\x00\x00\x00\x00"),
            ClientCharacteristicConfigurationDescriptor(13),
        ]

        ###
        # Initialize GATT state
        ###

        # ATT MTU
        self.__mtu = 23

        # No current procedure
        self.__cur_procedure = None


        # Register procedures
        self.__procedures = [
            ReadProcedure,
            ReadByGroupTypeProcedure,
            ReadByTypeProcedure,
            FindInformationProcedure,
        ]

    @property
    def attributes(self) -> list[Attribute]:
        """Server Attributes."""
        return self.__attributes

    def on_pdu(self, request: Packet) -> List[Packet]:
        """Process incoming request."""
        # Find a suitable procedure if none in progress
        if self.__cur_procedure is None:
            # Find a procedure triggered by our request
            for proc in self.__procedures:
                if proc.trigger(request):
                    self.__cur_procedure = proc(self.attributes, self.__mtu)

        if self.__cur_procedure is not None:
            # Forward to current procedure
            resp = self.__cur_procedure.process_request(request)
            if self.__cur_procedure.done():
                self.__cur_procedure = None
            return resp
        else:
            # Return an unlikely error
            return [ATT_Hdr()/ATT_Error_Response(opcode=request.opcode, handle=request.gatt_handle, ecode=0x0E)]

