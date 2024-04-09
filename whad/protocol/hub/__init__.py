"""WHAD Protocol Hub
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.hub.generic import Generic

class ProtocolHub(object):
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
    
    def parse(self, data: bytes):
        """Parse a serialized WHAD message into an associated object.
        """
        # Use protocol buffers to parse our message
        msg = Message()
        msg.ParseFromString(bytes(data))

        # Only process generic messages
        if msg.WhichOneof('msg') == 'generic':
            generic_msg = Generic.dispatch(self.__version, msg)
