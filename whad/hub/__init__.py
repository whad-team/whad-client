"""WHAD Protocol Hub

The protocol hub is a set of wrappers for Protobuf messages that provides a way
to support different versions of our communication protocol. This protocol hub
provides a default message parser handling different protocol versions that will
pick the correct message wrapper class to parse it. Message wrappers simplifies
the way protocol buffers messages are created by mapping some of their properties
to protobuf messages fields.
"""
import logging
from typing import Union
from whad.protocol.whad_pb2 import Message
from .registry import Registry

logger = logging.getLogger(__name__)

class ProtocolHub(Registry):
    """WHAD Protocol Hub class

    This class is an interface between all our Python code and the devices, that
    support all the existing versions of the WHAD protocol and handles every
    differences that exist between them in a transparent fashion.
    """

    NAME = 'hub'
    VERSIONS = {}

    def __init__(self, proto_version: int):
        """Instanciate a WHAD protocol hub for a specific version.
        """
        self.__version = proto_version

    @property
    def version(self) -> int:
        return self.__version

    @property
    def generic(self):
        return self.get('generic')

    @property
    def discovery(self):
        return self.get('discovery')

    @property
    def ble(self):
        return self.get('ble')

    @property
    def dot15d4(self):
        return self.get('dot15d4')

    @property
    def phy(self):
        return self.get('phy')

    @property
    def esb(self):
        return self.get('esb')

    @property
    def unifying(self):
        return self.get('unifying')

    def get(self, factory: str):
        return ProtocolHub.bound(factory, self.__version)(self.__version)

    def parse(self, data: Union[Message, bytes]):
        """Parse a serialized WHAD message into an associated object.
        """
        if isinstance(data, bytes):
            # Use protocol buffers to parse our message
            msg = Message()
            msg.ParseFromString(bytes(data))
        elif isinstance(data, Message):
            msg = data
        else:
            return None

        # Only process generic messages
        return ProtocolHub.bound(
            msg.WhichOneof('msg'),
            self.__version).parse(self.__version, msg)

    def convert_packet(self, packet):
        """Convert packet to the corresponding message.
        """
        msg = None
        # We dispatch packets based on their layers
        if self.ble.is_packet_compat(packet):
            logger.debug('[hub] convert_packet(): packet is BLE')
            msg = self.ble.convert_packet(packet)
        elif self.dot15d4.is_packet_compat(packet):
            logger.debug('[hub] convert_packet(): packet is Dot15d4')
            msg = self.dot15d4.convert_packet(packet)
        elif self.esb.is_packet_compat(packet):
            logger.debug('[hub] convert_packet(): packet is ESB')
            msg = self.esb.convert_packet(packet)
        elif self.phy.is_packet_compat(packet):
            logger.debug('[hub] convert_packet(): packet is PHY')
            msg = self.phy.convert_packet(packet)
        elif self.unifying.is_packet_compat(packet):
            logger.debug('[hub] convert_packet(): packet is Unifying')
            msg = self.unifying.convert_packet(packet)
        else:
            logger.error('[hub] convert_packet(): packet is unknown !')

        return msg



from .generic import Generic
from .discovery import Discovery
from .ble import BleDomain
from .dot15d4 import Dot15d4Domain
from .phy import PhyDomain
from .esb import EsbDomain
from .unifying import UnifyingDomain
