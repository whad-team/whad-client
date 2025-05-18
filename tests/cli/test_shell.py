"""Test command-line shell API
"""
import pytest
from whad.cli.shell import InteractiveShell, category

@pytest.fixture
def shell():
    """Interactive shell fixture.
    """
    class TestShell(InteractiveShell):
        """Interactive shell for testing
        """

        @category("test-category")
        def do_foo(self, args):
            """Default foo command

            This command does something.
            """
            return "foo"

        def do_bar(self, args):
            """Bar command

            This command does something else.
            """
            return "bar"
        
        def complete_foo(self):
            """Test auto-complete.
            """
            return {'this':None, 'that':None}

    return TestShell()


def test_shell_command_registration(shell):
    """Check shell command registration
    """
    assert shell.process("foo") == "foo"

def test_env_set(shell):
    """Test setting environment variable
    """
    shell.do_set(["test", "this is a test"])
    assert shell.resolve("$test") == "this is a test"

def test_env_unset(shell):
    """Test unsetting env variable
    """
    shell.do_set(["test", "this is a test"])
    shell.do_unset(["test"])
    assert shell.resolve("$test") == "$test"
