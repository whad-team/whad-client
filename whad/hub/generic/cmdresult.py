"""WHAD Protocol Generic CommandResult messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.generic_pb2 import ResultCode
from whad.hub.message import HubMessage,pb_bind
from whad.hub.generic import Generic

@pb_bind(Generic, 'cmd_result', 1)
class CommandResult(HubMessage):
    """CommandResult message class

    Provides a parsing method (`parse()`) to parse a CommandResult protocol
    buffers message into an object, based on its result code.
    """

    ERROR = ResultCode.ERROR
    SUCCESS = ResultCode.SUCCESS
    PARAMETER_ERROR = ResultCode.PARAMETER_ERROR
    DISCONNECTED = ResultCode.DISCONNECTED
    WRONG_MODE = ResultCode.WRONG_MODE
    UNSUPPORTED_DOMAIN = ResultCode.UNSUPPORTED_DOMAIN
    BUSY = ResultCode.BUSY


    def __init__(self, result_code: int = ResultCode.SUCCESS, message: Message = None):
        """Create a new CommandResult message with the associated protocol
        version number.
        """
        super().__init__(message=message)

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
        return super().serialize()

    @staticmethod
    def parse(version: int, msg):
        """Parse a protocol buffer message containing a CommandResult object
        into the corresponding generic message class.
        """
        if msg.generic.cmd_result.result == CommandResult.ERROR:
            return Generic.bound('cmd_result_error', version)(message=msg)
        elif msg.generic.cmd_result.result == CommandResult.SUCCESS:
            return Generic.bound('cmd_result_success', version)(message=msg)
        elif msg.generic.cmd_result.result == CommandResult.PARAMETER_ERROR:
            return Generic.bound('cmd_result_param_error', version)(message=msg)
        elif msg.generic.cmd_result.result == CommandResult.DISCONNECTED:
            return Generic.bound('cmd_result_disconnected', version)(message=msg)
        elif msg.generic.cmd_result.result == CommandResult.WRONG_MODE:
            return Generic.bound('cmd_result_wrong_mode', version)(message=msg)
        elif msg.generic.cmd_result.result == CommandResult.UNSUPPORTED_DOMAIN:
            return Generic.bound('cmd_result_unsupported_domain', version)(message=msg)
        elif msg.generic.cmd_result.result == CommandResult.BUSY:
            return Generic.bound('cmd_result_busy', version)(message=msg)


@pb_bind(Generic, 'cmd_result_error', 1)
class Error(CommandResult):
    """Generic error message.
    """

    def __init__(self, message: Message = None):
        """Create a CommandResult message with result code ERROR.
        """
        super().__init__(result_code=CommandResult.ERROR, message=message)

@pb_bind(Generic, 'cmd_result_success', 1)
class Success(CommandResult):
    """Generic success message.
    """

    def __init__(self, message: Message = None):
        """Create a CommandResult message with result code SUCCESS.
        """
        super().__init__(result_code=CommandResult.SUCCESS, message=message)

@pb_bind(Generic, 'cmd_result_param_error', 1)
class ParameterError(CommandResult):
    """Generic parameter error message.
    """

    def __init__(self, message: Message = None):
        """Create a CommandResult message with result code PARAMETER_ERROR.
        """
        super().__init__(result_code=CommandResult.PARAMETER_ERROR, message=message)

@pb_bind(Generic, 'cmd_result_disconnected', 1)
class Disconnected(CommandResult):
    """Generic disconnected message.
    """

    def __init__(self, message: Message = None):
        """Create a CommandResult message with result code DISCONNECTED.
        """
        super().__init__(result_code=CommandResult.DISCONNECTED, message=message)

@pb_bind(Generic, 'cmd_result_wrong_mode', 1)
class WrongMode(CommandResult):
    """Generic wrong mode message.
    """

    def __init__(self, message: Message = None):
        """Create a CommandResult message with result code WRONG_MODE.
        """
        super().__init__(result_code=CommandResult.WRONG_MODE, message=message)

@pb_bind(Generic, 'cmd_result_unsupported_domain', 1)
class UnsupportedDomain(CommandResult):
    """Generic unsupported domain error message.
    """

    def __init__(self, message: Message = None):
        """Create a CommandResult message with result code UNSUPPORTED_DOMAIN.
        """
        super().__init__(result_code=CommandResult.UNSUPPORTED_DOMAIN, message=message)

@pb_bind(Generic, 'cmd_result_busy', 1)
class Busy(CommandResult):
    """Generic busy message.
    """

    def __init__(self, message: Message = None):
        """Create a CommandResult message with result code BUSY.
        """
        super().__init__(result_code=CommandResult.BUSY, message=message)
