"""Protocol hub Generic messages unit tests
"""

from whad.protocol.whad_pb2 import Message
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.hub.generic import Generic, \
    Progress, Debug, Verbose
from whad.protocol.hub.generic.cmdresult import Success, Error, ParameterError, \
    WrongMode, Disconnected, Busy, UnsupportedDomain, CommandResult


class TestCommandResultParsing(object):
    """Unit tests for CommandResult parsing
    """

    def test_cmdresult_success_parsing(self):
        """Create a generic success message and check parsing
        """
        msg = Message()
        msg.generic.cmd_result.result = ResultCode.SUCCESS
        parsed_obj = CommandResult.parse(1, msg)
        assert isinstance(parsed_obj, Success)

    def test_cmdresult_error_parsing(self):
        """Create a generic error message and check parsing
        """
        msg = Message()
        msg.generic.cmd_result.result = ResultCode.ERROR
        parsed_obj = CommandResult.parse(1, msg)
        assert isinstance(parsed_obj, Error)

    def test_cmdresult_param_error_parsing(self):
        """Create a generic parameter error message and check parsing
        """
        msg = Message()
        msg.generic.cmd_result.result = ResultCode.PARAMETER_ERROR
        parsed_obj = CommandResult.parse(1, msg)
        assert isinstance(parsed_obj, ParameterError)

    def test_cmdresult_wrong_mode_parsing(self):
        """Create a generic parameter error message and check parsing
        """
        msg = Message()
        msg.generic.cmd_result.result = ResultCode.WRONG_MODE
        parsed_obj = CommandResult.parse(1, msg)
        assert isinstance(parsed_obj, WrongMode)

    def test_cmdresult_unsupported_domain_parsing(self):
        """Create a generic unsupported domain message and check parsing
        """
        msg = Message()
        msg.generic.cmd_result.result = ResultCode.UNSUPPORTED_DOMAIN
        parsed_obj = CommandResult.parse(1, msg)
        assert isinstance(parsed_obj, UnsupportedDomain)

    def test_cmdresult_busy_parsing(self):
        """Create a generic busy message and check parsing
        """
        msg = Message()
        msg.generic.cmd_result.result = ResultCode.BUSY
        parsed_obj = CommandResult.parse(1, msg)
        assert isinstance(parsed_obj, Busy)

    def test_cmdresult_disconnected_parsing(self):
        """Create a generic disconnected message and check parsing
        """
        msg = Message()
        msg.generic.cmd_result.result = ResultCode.DISCONNECTED
        parsed_obj = CommandResult.parse(1, msg)
        assert isinstance(parsed_obj, Disconnected)


class TestCommandResultCrafting(object):
    """Test generic command result crafting.
    """

    def test_cmdresult_success(self):
        """Create a Success() object and check result_code.
        """
        success = Success()
        assert success.result_code == ResultCode.SUCCESS

    def test_cmdresult_error(self):
        """Create a Error() object and check result_code.
        """
        success = Error()
        assert success.result_code == ResultCode.ERROR

    def test_cmdresult_param_error(self):
        """Create a ParameterError() object and check result_code.
        """
        success = ParameterError()
        assert success.result_code == ResultCode.PARAMETER_ERROR

    def test_cmdresult_wrong_mode(self):
        """Create a WrongMode() object and check result_code.
        """
        success = WrongMode()
        assert success.result_code == ResultCode.WRONG_MODE

    def test_cmdresult_unsupported_domain(self):
        """Create a UnsupportedDomain() object and check result_code.
        """
        success = UnsupportedDomain()
        assert success.result_code == ResultCode.UNSUPPORTED_DOMAIN

    def test_cmdresult_busy(self):
        """Create a Busy() object and check result_code.
        """
        success = Busy()
        assert success.result_code == ResultCode.BUSY

    def test_cmdresult_disconnected(self):
        """Create a Disconnected() object and check result_code.
        """
        success = Disconnected()
        assert success.result_code == ResultCode.DISCONNECTED


class TestProgress(object):
    """Test generic progress message parsing and crafting.
    """

    def test_progress_parsing(self):
        """Test generic progress message parsing.
        """
        msg = Message()
        msg.generic.progress.value = 100
        parsed_obj = Progress.parse(1, msg)
        assert isinstance(parsed_obj, Progress)
        assert parsed_obj.value == 100

    def test_progress_crafting(self):
        """Test generic progress message crafting.
        """
        obj = Progress(value=50)
        assert obj.value == 50

class TestDebug(object):
    """Test generic debug message parsing and crafting.
    """

    def test_debug_parsing(self):
        """Test generic debug message parsing.
        """
        msg = Message()
        msg.generic.debug.level = 42
        msg.generic.debug.data = b"Hello world !"
        parsed_obj = Debug.parse(1, msg)
        assert isinstance(parsed_obj, Debug)
        assert parsed_obj.msg == b"Hello world !"
        assert parsed_obj.level == 42

    def test_debug_crafting(self):
        """Test generic debug message crafting.
        """
        msg = Debug(level=42, msg=b"Hello world !")
        assert msg.msg == b"Hello world !"
        assert msg.level == 42

class TestVerbose(object):
    """Test generic verbose message parsing and crafting.
    """

    def test_verbose_parsing(self):
        """Test generic verbose message parsing.
        """
        msg = Message()
        msg.generic.verbose.data = b"Hello world !"
        parsed_obj = Verbose.parse(1, msg)
        assert isinstance(parsed_obj, Verbose)
        assert parsed_obj.msg == b"Hello world !"

    def test_verbose_crafting(self):
        """Test generic verbose message crafting.
        """
        msg = Verbose(msg=b"This is a test")
        assert msg.msg == b"This is a test"


class TestGeneric(object):
    """Test Generic parsing and crafting.
    """

    def test_cmdresult_parsing(self):
        """Test CommandResult message parsing
        """
        msg = Message()
        msg.generic.cmd_result.result = ResultCode.SUCCESS
        parsed_obj = Generic.parse(1, msg)
        assert isinstance(parsed_obj, CommandResult)


    def test_progress_parsing(self):
        """Test Progress message parsing
        """
        msg = Message()
        msg.generic.progress.value = 150
        parsed_obj = Generic.parse(1, msg)
        assert isinstance(parsed_obj, Progress)

    def test_debug_parsing(self):
        """Test Debug message parsing
        """
        msg = Message()
        msg.generic.debug.level = 1000
        msg.generic.debug.data = b"This is a test"
        parsed_obj = Generic.parse(1, msg)
        assert isinstance(parsed_obj, Debug)

    def test_verbose_parsing(self):
        """Test Verbose message parsing
        """
        msg = Message()
        msg.generic.verbose.data = b"This is a test"
        parsed_obj = Generic.parse(1, msg)
        assert isinstance(parsed_obj, Verbose)

    def test_error_factory(self):
        """Test generic message factory for error message crafting
        """
        generic = Generic(1)
        msg = generic.createError()
        assert isinstance(msg, Error)

    def test_success_factory(self):
        """Test generic message factory for success message crafting
        """
        generic = Generic(1)
        msg = generic.createSuccess()
        assert isinstance(msg, Success)

    def test_param_error_factory(self):
        """Test generic message factory for parameter error message crafting
        """
        generic = Generic(1)
        msg = generic.createParamError()
        assert isinstance(msg, ParameterError)

    def test_disconnected_factory(self):
        """Test generic message factory for disconnected error message crafting
        """
        generic = Generic(1)
        msg = generic.createDisconnected()
        assert isinstance(msg, Disconnected)

    def test_wrong_mode_factory(self):
        """Test generic message factory for wrong mode error message crafting
        """
        generic = Generic(1)
        msg = generic.createWrongMode()
        assert isinstance(msg, WrongMode)

    def test_unsupported_domain_factory(self):
        """Test generic message factory for unsupported domain error message crafting
        """
        generic = Generic(1)
        msg = generic.createUnsupportedDomain()
        assert isinstance(msg, UnsupportedDomain)

    def test_busy_factory(self):
        """Test generic message factory for unsupported busy error message crafting
        """
        generic = Generic(1)
        msg = generic.createBusy()
        assert isinstance(msg, Busy)

    def test_verbose_factory(self):
        """Test generic message factory for verbose message crafting
        """
        generic = Generic(1)
        msg = generic.createVerbose(b'TestMessage')
        assert isinstance(msg, Verbose)

    def test_debug_factory(self):
        """Test generic message factory for debug message crafting
        """
        generic = Generic(1)
        msg = generic.createDebug(42, b'TestMessage')
        assert isinstance(msg, Debug)

    def test_progress_factory(self):
        """Test generic message factory for progress message crafting
        """
        generic = Generic(1)
        msg = generic.createProgress(10)
        assert isinstance(msg, Progress)
        