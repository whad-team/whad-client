"""WHAD Protocol Generic CommandResult messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.hub.message import HubMessage

class CommandResult(HubMessage):
    """CommandResult message class

    Provides a parsing method (`parse()`) to parse a CommandResult protocol
    buffers message into an object, based on its result code.
    """

    def __init__(self, version: int, result_code: int = ResultCode.SUCCESS, message: Message = None):
        """Create a new CommandResult message with the associated protocol
        version number.
        """
        super().__init__(version, message=message)

        # If ProtoBuf message is provided, extract result code from message
        if message is not None:
            self.__result_code = message.generic.cmd_result.result

        # If result_code is provided, override result code value
        if result_code is not None:
            self.result_code = result_code

    @property
    def result_code(self) -> int:
        """Return the CommandResult result code.
        """
        return self.__result_code
    
    @result_code.setter
    def result_code(self, result_code: int):
        self.__result_code = result_code

    def serialize(self) -> bytes:
        """Serialize this message using Protobuf serialization routines.
        """
        self.message.generic.cmd_result.result = self.__result_code

    @staticmethod
    def parse(version: int, msg):
        """Parse a protocol buffer message containing a CommandResult object
        into the corresponding generic message class.
        """
        if msg.generic.cmd_result.result == ResultCode.ERROR:
            return Error(version, message=msg)
        elif msg.generic.cmd_result.result == ResultCode.SUCCESS:
            return Success(version, message=msg)
        elif msg.generic.cmd_result.result == ResultCode.PARAMETER_ERROR:
            return ParameterError(version, message=msg)
        elif msg.generic.cmd_result.result == ResultCode.DISCONNECTED:
            return Disconnected(version, message=msg)
        elif msg.generic.cmd_result.result == ResultCode.WRONG_MODE:
            return WrongMode(version, message=msg)
        elif msg.generic.cmd_result.result == ResultCode.UNSUPPORTED_DOMAIN:
            return UnsupportedDomain(version, message=msg)
        elif msg.generic.cmd_result.result == ResultCode.BUSY:
            return Busy(version, message=msg)


class Error(CommandResult):
    """Generic error message.
    """
    
    def __init__(self, version: int, message: Message = None):
        """Create a CommandResult message with result code ERROR.
        """
        super().__init__(version, result_code=ResultCode.ERROR, message=message)
    
class Success(CommandResult):
    """Generic success message.
    """

    def __init__(self, version: int, message: Message = None):
        """Create a CommandResult message with result code SUCCESS.
        """
        super().__init__(version, result_code=ResultCode.SUCCESS, message=message)

class ParameterError(CommandResult):
    """Generic parameter error message.
    """

    def __init__(self, version: int, message: Message = None):
        """Create a CommandResult message with result code PARAMETER_ERROR.
        """
        super().__init__(version, result_code=ResultCode.PARAMETER_ERROR, message=message)

class Disconnected(CommandResult):
    """Generic disconnected message.
    """

    def __init__(self, version: int, message: Message = None):
        """Create a CommandResult message with result code DISCONNECTED.
        """
        super().__init__(version, result_code=ResultCode.DISCONNECTED, message=message)

class WrongMode(CommandResult):
    """Generic wrong mode message.
    """

    def __init__(self, version: int, message: Message = None):
        """Create a CommandResult message with result code WRONG_MODE.
        """
        super().__init__(version, result_code=ResultCode.WRONG_MODE, message=message) 

class UnsupportedDomain(CommandResult):
    """Generic unsupported domain error message.
    """

    def __init__(self, version: int, message: Message = None):
        """Create a CommandResult message with result code UNSUPPORTED_DOMAIN.
        """
        super().__init__(version, result_code=ResultCode.UNSUPPORTED_DOMAIN, message=message)

class Busy(CommandResult):
    """Generic busy message.
    """

    def __init__(self, version: int, message: Message = None):
        """Create a CommandResult message with result code BUSY.
        """
        super().__init__(version, result_code=ResultCode.BUSY, message=message)