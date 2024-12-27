"""Test Command-line application helpers
"""
from whad.cli.app import command, CommandsRegistry

def test_command_registration():
    """Register a command and check it has correctly been registered
    by the CommandsRegistry.
    """
    @command("test")
    def test_command():
        """This is a test command
        """

    assert CommandsRegistry.get_handler("test") is not None
    assert CommandsRegistry.get_short_desc("test") == "This is a test command"
