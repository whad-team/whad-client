"""WHAD protocol message abstraction
"""
from whad.protocol.whad_pb2 import Message

class HubMessage(object):
    """Main class from which any ProtocolHub message derives from.
    """

    def __init__(self, version: int, message: Message = None):
        self.__proto_version = version
        if message is None:
            self.__msg = Message()
        else:
            self.__msg = message

    def serialize(self):
        return self.__msg.SerializeToString()

    @property
    def proto_version(self):
        return self.__proto_version
    

    @property
    def message(self):
        return self.__msg