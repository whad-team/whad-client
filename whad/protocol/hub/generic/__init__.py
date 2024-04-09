"""WHAD Protocol Generic message abstraction layer.
"""
from whad.protocol.hub.message import HubMessage
from whad.protocol.hub import pb_bind, Registry, ProtocolHub

@pb_bind(ProtocolHub, name='generic', version=1)
class Generic(Registry):
    """WHAD Generic message parser/factory.
    """

    def __init__(self, version: int):
        self.proto_version = version

    @staticmethod
    def parse(proto_version: int, message) -> HubMessage:
        """Parses a WHAD generic message as seen by protobuf
        """
        message_type = message.generic.WhichOneof('msg')
        message_clazz = Generic.bound(message_type, proto_version)
        return message_clazz.parse(proto_version, message)
    
    def createCommandResult(self, result_code: int) -> HubMessage:
        """Create a generic command result.
        """
        return Generic.bound('cmd_result', self.proto_version)(
            self.proto_version, result_code = result_code
        )
    
    def createDebugMessage(self, level: int, message: bytes) -> HubMessage:
        """Create a debug message.
        """
        return Generic.bound('debug', self.proto_version)(
            self.proto_version, debug_level=level, debug_msg=message
        )
    
    def createVerboseMessage(self, message: bytes) -> HubMessage:
        """Create a verbose message.
        """
        return Generic.bound('debug', self.proto_version)(
            self.proto_version, data=message
        )
    
    def createProgressMessage(self, value: int) -> HubMessage:
        """Create a progress message.
        """
        return Generic.bound('debug', self.proto_version)(
            self.proto_version, value=value
        )

from .cmdresult import CommandResult
from .debug import Debug
from .verbose import Verbose
from .progress import Progress

__all__ = [
    'Generic',
    'CommandResult',
    'Success',
    'Error',
    'ParameterError',
    'WrongMode',
    'UnsupportedDomain',
    'Disconnected',
    'Busy',
    'Debug',
    'Verbose',
    'Progress'
]