"""WHAD Protocol Generic Progress message abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.hub.message import HubMessage


class Progress(HubMessage):
    """Progress message class.
    """

    def __init__(self, version: int, value: int = None, message: Message = None):
        """Create a generic progress message.
        """
        super().__init__(version, message=message)

        # Default values
        self.__progress_value = 0

        # Extract progress value
        if message is not None:
            self.__progress_value = message.generic.progress.value

        # Override with value if given
        if value is not None:
            self.__progress_value = value

    @property
    def value(self) -> int:
        """Retrieve the progress value.
        """
        return self.__progress_value

    @value.setter
    def value(self, val: int):
        """Set the progress value.
        """
        self.__progress_value = val

    def serialize(self) -> bytes:
        """Update message and serialize.
        """
        self.message.generic.progress.value = self.__progress_value
        return super().serialize()

    @staticmethod
    def parse(version: int, message: Message):
        """Parse a generic progress message.
        """
        return Progress(version, message=message)