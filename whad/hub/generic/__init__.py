"""WHAD Protocol Generic message abstraction layer.
"""
from whad.hub.message import HubMessage, pb_bind, Registry
from whad.hub import ProtocolHub

@pb_bind(ProtocolHub, name='generic', version=1)
class Generic(Registry):
    """WHAD Generic message parser/factory.
    """

    VERSIONS = {}

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
            result_code = result_code
        )
    
    def createError(self) -> HubMessage:
        """Create a generic error message.
        """
        return Generic.bound('cmd_result_error', self.proto_version)()

    def createSuccess(self) -> HubMessage:
        """Create a generic success result.
        """
        return Generic.bound('cmd_result_success', self.proto_version)()
    
    def createParamError(self) -> HubMessage:
        """Create a parameter error message.
        """
        return Generic.bound('cmd_result_param_error', self.proto_version)()
    
    def createDisconnected(self) -> HubMessage:
        """Create a disconnected error message.
        """
        return Generic.bound('cmd_result_disconnected', self.proto_version)() 

    def createWrongMode(self) -> HubMessage:
        """Create a wrong mode error message.
        """
        return Generic.bound('cmd_result_wrong_mode', self.proto_version)()
    
    def createUnsupportedDomain(self) -> HubMessage:
        """Create an unsupported domain error message.
        """
        return Generic.bound('cmd_result_unsupported_domain', self.proto_version)()
    
    def createBusy(self) -> HubMessage:
        """Create a busy error message.
        """
        return Generic.bound('cmd_result_busy', self.proto_version)()

    def createDebug(self, level: int, message: bytes) -> HubMessage:
        """Create a debug message.
        """
        return Generic.bound('debug', self.proto_version)(
            debug_level=level, debug_msg=message
        )
    
    def createVerbose(self, message: bytes) -> HubMessage:
        """Create a verbose message.
        """
        return Generic.bound('verbose', self.proto_version)(
            data=message
        )
    
    def createProgress(self, value: int) -> HubMessage:
        """Create a progress message.
        """
        return Generic.bound('progress', self.proto_version)(
            value=value
        )

from .cmdresult import CommandResult
from .debug import Debug
from .verbose import Verbose
from .progress import Progress

__all__ = [
    'Generic',
    'CommandResult',
    'Debug',
    'Verbose',
    'Progress'
]