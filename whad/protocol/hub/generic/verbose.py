"""WHAD Protocol Generic Verbose message abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.hub.message import HubMessage

class Verbose(HubMessage):
    """Generic verbose message class.
    """

    def __init__(self, version: int, data: bytes = None, message: Message = None):
        """Create a generic verbose message.
        """
        super().__init__(version, message=message)

        # Extract verbose data from message if provided
        if message is not None:
            self.__verb_data = message.generic.verbose.data
        else:
            self.__verb_data = b""

        # Override verbose data if specified
        if data is not None:
            self.__verb_data = data


    @property
    def data(self) -> bytes:
        """Retrieve the verbose message data.
        """
        return self.__verb_data
    
    @data.setter
    def data(self, value: bytes):
        """Set verbose message data.
        """
        self.__verb_data = value

    def serialize(self) -> bytes:
        """Update message and serialize.
        """
        self.message.generic.verbose.data = self.__verb_data
        return super().serialize()
    
    @staticmethod
    def parse(version: int, message: Message):
        """Parse a generic verbose message.
        """
        return Verbose(version, message=message)