"""WHAD Protocol Hub

The protocol hub is a set of wrappers for Protobuf messages that provides a way
to support different versions of our communication protocol. This protocol hub
provides a default message parser handling different protocol versions that will
pick the correct message wrapper class to parse it. Message wrappers simplifies
the way protocol buffers messages are created by mapping some of their properties
to protobuf messages fields.
"""

from whad.protocol.whad_pb2 import Message
from .registry import Registry

class ProtocolHub(Registry):
    """WHAD Protocol Hub class

    This class is an interface between all our Python code and the devices, that
    support all the existing versions of the WHAD protocol and handles every
    differences that exist between them in a transparent fashion.
    """

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

    def get(self, factory: str):
        return ProtocolHub.bound(factory, self.__version)(self.__version)

    def parse(self, data: bytes):
        """Parse a serialized WHAD message into an associated object.
        """
        # Use protocol buffers to parse our message
        msg = Message()
        msg.ParseFromString(bytes(data))

        # Only process generic messages
        return ProtocolHub.bound(
            msg.WhichOneof('msg'),
            self.__version).parse(self.__version, msg)

from .generic import Generic
from .discovery import Discovery
from .ble import BleDomain
from .dot15d4 import Dot15d4Domain
from .phy import PhyDomain