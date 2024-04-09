"""WHAD Protocol Generic Debug message abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.hub.message import HubMessage

class Debug(HubMessage):
    """Generic debug message.
    """

    def __init__(self, version: int, debug_level: int = None, debug_msg: bytes = None, message: Message = None):
        """Create a generic debug message.
        """
        super().__init__(version, message=message)

        # Default values
        self.__debug_msg = b""
        self.__debug_level = 0

        # Set debug message
        if message is not None:
            self.__debug_msg = message.generic.debug.data
            self.__debug_level = message.generic.debug.level

        # Override debug message if required
        if debug_msg is not None:
            self.__debug_msg = debug_msg

        # Override debug level if required
        if debug_level is not None:
            self.__debug_level = debug_level

    @property
    def data(self) -> bytes:
        """Retrieve debug message data.
        """
        return self.__debug_msg
    
    @data.setter
    def data(self, msg: bytes):
        """Set debug message data.
        """
        self.__debug_msg = msg

    @property
    def level(self) -> int:
        """Retrieve the associated debug level
        """
        return self.__debug_level
    
    @level.setter
    def level(self, value: int):
        """Set debug level.
        """
        self.__debug_level = value

    def serialize(self):
        """Serialize generic debug message.
        """
        self.message.generic.debug.level = self.__debug_level
        self.message.generic.debug.data = self.__debug_msg
        return super().serialize()

    @staticmethod
    def parse(version: int, message: Message):
        """Parse a generic debug message.
        """
        return Debug(version, message=message)