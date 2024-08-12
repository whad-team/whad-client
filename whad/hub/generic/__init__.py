"""WHAD Protocol Generic message abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.hub.message import HubMessage, pb_bind, Registry, PbMessageWrapper
from whad.hub import ProtocolHub

@pb_bind(ProtocolHub, name='generic', version=1)
class Generic(Registry):
    """WHAD Generic message parser/factory.
    """

    NAME = 'generic'
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

    def create_command_result(self, result_code: int) -> HubMessage:
        """Create a generic command result.
        """
        # Map our result code to our dedicated methods
        result_types = {
            CommandResult.SUCCESS: self.create_success,
            CommandResult.ERROR: self.create_error,
            CommandResult.PARAMETER_ERROR: self.create_param_error,
            CommandResult.BUSY: self.create_busy,
            CommandResult.DISCONNECTED: self.create_disconnected,
            CommandResult.WRONG_MODE: self.create_wrong_mode,
        }

        # Dispatch to our specific factory methods for command result.
        if result_code in result_types:
            return result_types[result_code]()
        else:
            raise ValueError()

    def create_error(self) -> HubMessage:
        """Create a generic error message.
        """
        return Generic.bound('cmd_result_error', self.proto_version)()

    def create_success(self) -> HubMessage:
        """Create a generic success result.
        """
        return Generic.bound('cmd_result_success', self.proto_version)()

    def create_param_error(self) -> HubMessage:
        """Create a parameter error message.
        """
        return Generic.bound('cmd_result_param_error', self.proto_version)()

    def create_disconnected(self) -> HubMessage:
        """Create a disconnected error message.
        """
        return Generic.bound('cmd_result_disconnected', self.proto_version)()

    def create_wrong_mode(self) -> HubMessage:
        """Create a wrong mode error message.
        """
        return Generic.bound('cmd_result_wrong_mode', self.proto_version)()

    def create_unsupported_domain(self) -> HubMessage:
        """Create an unsupported domain error message.
        """
        return Generic.bound('cmd_result_unsupported_domain', self.proto_version)()

    def create_busy(self) -> HubMessage:
        """Create a busy error message.
        """
        return Generic.bound('cmd_result_busy', self.proto_version)()

    def create_debug(self, level: int, message: bytes) -> HubMessage:
        """Create a debug message.
        """
        return Generic.bound('debug', self.proto_version)(
            debug_level=level, debug_msg=message
        )

    def create_verbose(self, message: bytes) -> HubMessage:
        """Create a verbose message.
        """
        return Generic.bound('verbose', self.proto_version)(
            data=message
        )

    def create_progress(self, value: int) -> HubMessage:
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
