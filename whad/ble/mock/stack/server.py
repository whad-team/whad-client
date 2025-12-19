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
import logging
from struct import pack

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Hdr

from whad.ble.profile.attribute import UUID

from .attribute import Attribute, PrimaryService, Characteristic, CharacteristicValue, \
    ClientCharacteristicConfigurationDescriptor

# ATT Procedures
from .procedure import UnexpectedProcError
from .read import ServerReadProcedure
from .readblob import ServerReadBlobProcedure
from .read_by_group_type import ServerReadByGroupTypeProcedure
from .read_by_type import ServerReadByTypeProcedure
from .find_info import ServerFindInformationProcedure, ServerFindByTypeValueProcedure
from .write import ServerWriteProcedure
from .writecmd import ServerWriteCommandProcedure

logger = logging.getLogger(__name__)

class GattServer:
    """Tiny GATT server"""

    def __init__(self, l2cap: 'Llcap' = None):
        """Initialize a GATT server."""
        ###
        # Initialize GATT attributes
        ###

        # Save L2CAP reference
        self.__l2cap = l2cap

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
                Characteristic.PROP_READ | Characteristic.PROP_NOTIFY
            )),
            CharacteristicValue(6, UUID(0x2A19), pack("<H", 0)),
            ClientCharacteristicConfigurationDescriptor(7),

            # Primary Service, custom service (6d02b602-1b51-4ef9-b753-1399e05debfd), handle 7-10
            PrimaryService(8, 13, UUID("6d02b600-1b51-4ef9-b753-1399e05debfd")),

            # TX Characteristic
            Characteristic(9, UUID("6d02b601-1b51-4ef9-b753-1399e05debfd"), value_handle=10, properties=(
                Characteristic.PROP_WRITE_WITHOUT_RESP
            )),
            CharacteristicValue(10, UUID("6d02b601-1b51-4ef9-b753-1399e05debfd"), b"\x00\x00\x00\x00",
                                write_without_resp=True),

            # RX Characteristic
            Characteristic(11, UUID("6d02b602-1b51-4ef9-b753-1399e05debfd"), value_handle=12, properties=(
                Characteristic.PROP_READ |  Characteristic.PROP_NOTIFY | Characteristic.PROP_INDICATE
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
            ServerReadProcedure,
            ServerReadBlobProcedure,
            ServerWriteProcedure,
            ServerWriteCommandProcedure,
            ServerReadByGroupTypeProcedure,
            ServerReadByTypeProcedure,
            ServerFindInformationProcedure,
            ServerFindByTypeValueProcedure,
        ]

    @property
    def attributes(self) -> list[Attribute]:
        """Server Attributes."""
        return self.__attributes

    def set_l2cap(self, obj):
        """Set L2CAP layer for this GattClient."""
        self.__l2cap = obj

    def on_pdu(self, request: Packet) -> list[Packet]:
        """Process incoming request."""
        # Find a suitable procedure if none in progress
        if self.__cur_procedure is None:
            # Find a procedure triggered by our request
            for proc in self.__procedures:
                if proc.trigger(request):
                    self.__cur_procedure = proc(self.attributes, self.__mtu)

        # If a suitable procedure has been found or is in progress, forward request.
        if self.__cur_procedure is not None:
            # Forward to current procedure
            answers: list[Packet] = self.__cur_procedure.process_request(request)

            # Unset current procedure if finished
            if self.__cur_procedure.done():
                self.__cur_procedure = None

            # Automatically add ATT_Hdr()
            if isinstance(answers, list):
                return [ ATT_Hdr()/ans for ans in answers ]
            else:
                # Should not happen so raise an exception
                raise UnexpectedProcError()
        else:
            logger.warning("[ble::mock::stack::gatt_server] No procedure to handle packet ! (%s)", request)
            return []

