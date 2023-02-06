"""Command-line interface application module
"""
import os
import sys
from argparse import ArgumentParser
from prompt_toolkit import print_formatted_text, HTML
from prompt_toolkit.styles import Style

from whad.device import WhadDevice
from whad.exceptions import WhadDeviceAccessDenied, WhadDeviceNotFound, \
    WhadDeviceNotReady

class command(object):
    """CommandLineApp command decorator.

    This decorator must be used to register a specific command in the main
    application. You need to provide a short description and a detailed
    description of the command (HTML allowed).
    """

    def __init__(self, cmd_name, short_desc=None, desc=None):
        self.cmd_name = cmd_name
        self.short_desc = short_desc
        self.desc = desc

    def __call__(self, handler):
        CommandsRegistry.register(
            self.cmd_name,
            handler
        )

class CommandsRegistry:
    """Static registry used to keep track of defined commands and their
    associated documentation.
    """

    COMMANDS = {}
    CMDS_SHORT_DESC = {}
    CMDS_DESC = {}

    @staticmethod
    def register(command, handler):
        CommandsRegistry.COMMANDS[command] = handler

        # Extract short desc and description from docstring
        if hasattr(handler, '__doc__'):
            docstr = getattr(handler, '__doc__')
            short_desc = docstr.splitlines()[0].lstrip()
            desc = '\n'.join([l.lstrip() for l in docstr.splitlines()[1:]])
        else:
            short_desc = ''
            desc = ''

        if short_desc is not None:
            CommandsRegistry.CMDS_SHORT_DESC[command] = short_desc
        if desc is not None:
            CommandsRegistry.CMDS_DESC[command] = desc
    
    @staticmethod
    def get_handler(command):
        if command in CommandsRegistry.COMMANDS:
            return CommandsRegistry.COMMANDS[command]
        else:
            return None

    @staticmethod
    def get_short_desc(command):
        if command in CommandsRegistry.CMDS_SHORT_DESC:
            return CommandsRegistry.CMDS_SHORT_DESC[command]
        else:
            return None

    @staticmethod
    def get_desc(command):
        if command in CommandsRegistry.CMDS_DESC:
            return CommandsRegistry.CMDS_DESC[command]
        else:
            return None

    @staticmethod
    def enumerate():
        for command in CommandsRegistry.COMMANDS:
            yield (
                command,
                CommandsRegistry.get_short_desc(command),
                CommandsRegistry.get_desc(command)
            )


@command('help')
def show_default_help(app, args):
    """show this help screen

    <ansimagenta><b>help</b> <i>[command]</i></ansimagenta>

    Show contextual help for the provided <i>command</i>
    """
    if len(args) == 0:
        print_formatted_text(HTML('<ansimagenta><b>Available commands:</b></ansimagenta>'))
        commands = []
        for command, short_desc, _ in CommandsRegistry.enumerate():
            commands.append((command, short_desc))
        commands.sort()

        # Compute the longest command
        max_cmd_size = max([len(cmd) for cmd,doc in commands])
        cmd_fmt = "<ansicyan>{0:<%d}</ansicyan>\t\t{1}" % max_cmd_size
        for cmd, doc in commands:
            print_formatted_text(HTML(cmd_fmt.format(cmd, doc)))
    else:
        cmd = args[0]
        cmd_sd = CommandsRegistry.get_short_desc(cmd)
        cmd_desc = CommandsRegistry.get_desc(cmd)
        print_formatted_text(HTML(cmd_desc.strip()))

class CommandLineApp(ArgumentParser):

    """This class provides a wrap-up for WHAD CLI applications, adding
    a common default options:
    
     --interface/-i: specifies the WHAD interface to use
     --no-color: tells the application not to use colors in terminal

    It also provides a unified way to handle error/warning/info display,
    as well as a convenient way to add specific commands and associated
    handlers.

    Application arguments are expected to follow this pattern:

    $ app [--option [,--option]] [command] [command_arg [, command_arg]]

    Each command is associated to a specific handler that will take care of
    command arguments.
    """

    DEV_NOT_FOUND_ERR = -1
    DEV_NOT_READY_ERR = -2
    DEV_ACCESS_ERR = -3

    def __init__(self, description: str = None, commands: bool=True, interface: bool=True):
        """Instanciate a CommandLineApp

        :param str program_name: program (app) name
        :param str usage: usage string
        :param str description: program description
        :param bool commands: if enabled, the application will consider first positional argument as a command
        :param bool interface: if enabled, the application will resolve a WHAD interface
        """
        super().__init__(description=description)

        self.__interface = None
        self.__args = None
        self.__has_interface = interface
        self.__has_commands = commands

        # Add our default option --interface/-i
        if self.__has_interface:
            self.add_argument(
                '--interface', '-i',
                dest='interface',
                help='specifies the WHAD interface to use',
            )

        # Add our default option --no-color
        self.add_argument(
            '--no-color',
            dest='nocolor',
            action='store_true',
            default=False,
            help='disable colors in output'
        )

        # Save application type
        if self.__has_commands:
            self.add_argument(
                'command',
                metavar='COMMAND',
                nargs='?',
                help="command to execute, use 'help' for a list of supported commands"
            )
            self.add_argument(
                'command_args',
                metavar='COMMAND_ARG',
                nargs='*',
                help="command arguments"
            )

    @property
    def interface(self):
        """Return the selected WHAD interface.

        :return WhadDevice: Selected WHAD interface if any, None otherwise.
        """
        return self.__interface

    @property
    def args(self):
        """Return the parsed arguments Namespace.
        """
        return self.__args

    def pre_run(self):
        """Prepare run for this application

        - parses arguments
        - handling color settings
        - resolve WHAD interface
        """
        # First we need to parse the main arguments
        self.__args = self.parse_args()

        # If no color is enabled, change color depth to 1 (black/white)
        if self.__args.nocolor:
            os.environ['PROMPT_TOOLKIT_COLOR_DEPTH']='DEPTH_1_BIT'

        # If interface is provided, instanciate it and make it available
        if self.__has_interface:
            if self.__args.interface is not None:
                try:
                    # Create WHAD interface
                    self.__interface = WhadDevice.create(self.__args.interface)
                except WhadDeviceNotFound as dev_404:
                    self.error('WHAD device not found.')
                    return self.DEV_NOT_FOUND_ERR
                except WhadDeviceAccessDenied as dev_403:
                    self.error('Cannot access WHAD device, please check permissions.')
                    return self.DEV_ACCESS_ERR
                except WhadDeviceNotReady as dev_500:
                    self.error('WHAD device is not ready.')
                    return self.DEV_NOT_READY_ERR

    def post_run(self):
        """Implement post-run tasks.
        """
        pass

    def run(self):
        """Run the main application
        """
        # Launch pre-run tasks
        self.pre_run()

        # If we support first positional arg as command, parse the command
        if self.__has_commands:
            if self.__args.command is not None:
                command = self.__args.command
                handler = CommandsRegistry.get_handler(command)
                if handler is not None:
                    return handler(self, self.__args.command_args)

            # By default, print help if no script is specified
            self.print_help()

        # Launch post-run tasks
        self.post_run()


    def is_stdout_piped(self):
        """Checks if stdout is piped to another process

        :return bool: True if stdout is piped, False otherwise
        """
        return (not sys.stdout.isatty())


    def is_stdin_piped(self):
        """Checks if stdin is piped by another process

        :return bool: True if stdin is piped, False otherwise
        """
        return (not sys.stdin.isatty())


    def warning(self, message):
        """Display a warning message in orange (if color is enabled)
        """
        print_formatted_text(HTML('<aaa fg="#e97f11">/!\\ <b>%s</b></aaa>' % message))

    def error(self, message):
        """Display an error message in red (if color is enabled)
        """
        print_formatted_text(HTML('<ansired>[!] <b>%s</b></ansired>' % message))


if __name__ == '__main__':

    @command('test', 'this is a small test command', 'detailed desc')
    def test_handler(app, args):
        """Handle test command
        """
        print('this is a test with args: %s' % args)

    app = CommandLineApp('cli-demo',description='Whad CLI demo')
    app.run()

