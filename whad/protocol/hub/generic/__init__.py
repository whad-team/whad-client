"""WHAD Protocol Generic message abstraction layer.
"""
from whad.protocol.hub.message import HubMessage
from .cmdresult import CommandResult, Success, Error, ParameterError, WrongMode, \
    UnsupportedDomain, Disconnected, Busy
from .debug import Debug
from .progress import Progress
from .verbose import Verbose

class Generic(HubMessage):
    """WHAD Generic message parser/factory.
    """

    def __init__(self, version: int):
        super().__init__(version)

    @staticmethod
    def parse(proto_version: int, message) -> HubMessage:
        """Parses a WHAD generic message as seen by protobuf
        """
        if message.generic.WhichOneof('msg') == 'cmd_result':
            return CommandResult.parse(proto_version, message)
        elif message.generic.WhichOneof('msg') == 'progress':
            return Progress.parse(proto_version, message)
        elif message.generic.WhichOneof('msg') == 'debug':
            return Debug.parse(proto_version, message)
        elif message.generic.WhichOneof('msg') == 'verbose':
            return Verbose.parse(proto_version, message)
        
    def createCommandResult(self, result_code: int) -> CommandResult:
        """Create a generic command result.
        """
        return CommandResult(self.proto_version, result_code = result_code)
    
    def createResultSuccess(self) -> Success:
        """Create a result success message.
        """
        return Success(self.proto_version)
    
    def createResultError(self) -> Error:
        """Create a generic error message.
        """
        return Error(self.proto_version)
    
    def createParamError(self) -> ParameterError:
        """Create a generic parameter error message.
        """
        return ParameterError(self.proto_version)
    
    def createWrongModeError(self) -> WrongMode:
        """Create a wrong mode error message.
        """
        return WrongMode(self.proto_version)
    
    def createDisconnectedError(self) -> Disconnected:
        """Create a disconnected error message.
        """
        return Disconnected(self.proto_version)
    
    def createUnsupportedDomainError(self) -> UnsupportedDomain:
        """Create an unsupported domain error message.
        """
        return UnsupportedDomain(self.proto_version)
    
    def createBusyError(self) -> Busy:
        """Create a busy error message.
        """
        return Busy(self.proto_version)
    
    def createDebugMessage(self, level: int, message: bytes) -> Debug:
        """Create a debug message.
        """
        return Debug(self.proto_version, debug_level=level, debug_msg=message)
    
    def createVerboseMessage(self, message: bytes) -> Verbose:
        """Create a verbose message.
        """
        return Verbose(self, data=message)
    
    def createProgressMessage(self, value: int) -> Progress:
        """Create a progress message.
        """
        return Progress(self.proto_version, value=value)


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