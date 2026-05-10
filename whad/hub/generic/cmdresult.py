"""WHAD Protocol Generic CommandResult messages abstraction layer.
"""
from re import I
from whad.protocol.whad_pb2 import Message
from whad.protocol.generic_pb2 import ResultCode
from whad.hub.message import HubMessage, PbMessageWrapper,pb_bind, PbFieldInt
from whad.hub.generic import Generic

@pb_bind(Generic, 'cmd_result', 1)
class CommandResult(PbMessageWrapper):
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

    result = PbFieldInt('generic.cmd_result.result')

    @property
    def result_code(self):
        return self.result

    @result_code.setter
    def result_code(self, value):
        self.result = value

    @classmethod
    def parse(cls, version: int, message: HubMessage):
        """Parse a protocol buffer message containing a CommandResult object
        into the corresponding generic message class.
        """
        # Parse message
        result = message.generic.cmd_result.result

        # Create message based on return value.
        if result == CommandResult.SUCCESS:
            return Generic.build('cmd_result_success', version)
        elif result == CommandResult.PARAMETER_ERROR:
            return Generic.build('cmd_result_param_error', version)
        elif result == CommandResult.DISCONNECTED:
            return Generic.build('cmd_result_disconnected', version)
        elif result == CommandResult.WRONG_MODE:
            return Generic.build('cmd_result_wrong_mode', version)
        elif result == CommandResult.UNSUPPORTED_DOMAIN:
            return Generic.build('cmd_result_unsupported_domain', version)
        elif result == CommandResult.BUSY:
            return Generic.build('cmd_result_busy', version)
        return Generic.build('cmd_result_error', version)

@pb_bind(Generic, 'cmd_result_error', 1)
class Error(CommandResult):
    """Generic error message.
    """

    def __init__(self, version: int = 1, message: Message = None):
        """Create a CommandResult message with result code ERROR.
        """
        super().__init__(version, result=CommandResult.ERROR, message=message)

@pb_bind(Generic, 'cmd_result_success', 1)
class Success(CommandResult):
    """Generic success message.
    """

    def __init__(self, version: int = 1, message: Message = None):
        """Create a CommandResult message with result code SUCCESS.
        """
        super().__init__(version, result=CommandResult.SUCCESS, message=message)

@pb_bind(Generic, 'cmd_result_param_error', 1)
class ParameterError(CommandResult):
    """Generic parameter error message.
    """

    def __init__(self, version: int = 1, message: Message = None):
        """Create a CommandResult message with result code PARAMETER_ERROR.
        """
        super().__init__(version, result=CommandResult.PARAMETER_ERROR, message=message)

@pb_bind(Generic, 'cmd_result_disconnected', 1)
class Disconnected(CommandResult):
    """Generic disconnected message.
    """

    def __init__(self, version: int = 1, message: Message = None):
        """Create a CommandResult message with result code DISCONNECTED.
        """
        super().__init__(version, result=CommandResult.DISCONNECTED, message=message)

@pb_bind(Generic, 'cmd_result_wrong_mode', 1)
class WrongMode(CommandResult):
    """Generic wrong mode message.
    """

    def __init__(self, version: int = 1, message: Message = None):
        """Create a CommandResult message with result code WRONG_MODE.
        """
        super().__init__(version, result=CommandResult.WRONG_MODE, message=message)

@pb_bind(Generic, 'cmd_result_unsupported_domain', 1)
class UnsupportedDomain(CommandResult):
    """Generic unsupported domain error message.
    """

    def __init__(self, version: int = 1, message: Message = None):
        """Create a CommandResult message with result code UNSUPPORTED_DOMAIN.
        """
        super().__init__(version, result=CommandResult.UNSUPPORTED_DOMAIN, message=message)

@pb_bind(Generic, 'cmd_result_busy', 1)
class Busy(CommandResult):
    """Generic busy message.
    """

    def __init__(self, version: int = 1, message: Message = None):
        """Create a CommandResult message with result code BUSY.
        """
        super().__init__(version, result=CommandResult.BUSY, message=message)

