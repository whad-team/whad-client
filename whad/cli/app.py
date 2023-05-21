"""Command-line interface application module
"""
import os
import sys
import select
import fcntl
from argparse import ArgumentParser
from prompt_toolkit import print_formatted_text, HTML
from prompt_toolkit.output import create_output
from prompt_toolkit.application.current import get_app_session

from urllib.parse import urlparse, parse_qsl
from signal import signal, SIGPIPE, SIG_DFL

from whad.device import WhadDevice, UnixSocketDevice
from whad.exceptions import WhadDeviceAccessDenied, WhadDeviceNotFound, \
    WhadDeviceNotReady

import logging
logger = logging.getLogger(__name__)

signal(SIGPIPE,SIG_DFL)

class command(object):
    """CommandLineApp command decorator.

    This decorator must be used to register a specific command in the main
    application. You need to provide a short description and a detailed
    description of the command (HTML allowed).
    """

    def __init__(self, cmd_name, short_desc=None, desc=None, category='Generic commands'):
        self.cmd_name = cmd_name
        self.short_desc = short_desc
        self.desc = desc
        self.category = category

    def __call__(self, handler):
        CommandsRegistry.register(
            self.cmd_name,
            handler,
            self.category
        )

class CommandsRegistry:
    """Static registry used to keep track of defined commands and their
    associated documentation.
    """

    COMMANDS = {}
    CMDS_SHORT_DESC = {}
    CMDS_DESC = {}
    CATEGORIES = {}

    @staticmethod
    def register(command, handler, category):
        """Register a command
        """
        # Add command to our list of known commands
        CommandsRegistry.COMMANDS[command] = handler

        # Add command to the corresponding category
        if category not in CommandsRegistry.CATEGORIES:
            CommandsRegistry.CATEGORIES[category] = []
        CommandsRegistry.CATEGORIES[category].append(command)

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
    def enumerate_categories():
        for category in CommandsRegistry.CATEGORIES:
            yield category

    @staticmethod
    def enumerate(category=None):
        if category is None:
            for command in CommandsRegistry.COMMANDS:
                yield (
                    command,
                    CommandsRegistry.get_short_desc(command),
                    CommandsRegistry.get_desc(command)
                )
        else:
            for command in CommandsRegistry.COMMANDS:
                if command in CommandsRegistry.CATEGORIES[category]:
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
        # Enumerate commands by group
        for category in CommandsRegistry.enumerate_categories():
            print_formatted_text(HTML('<ansimagenta><b>%s:</b></ansimagenta>' % category))
            commands = []
            for command, short_desc, _ in CommandsRegistry.enumerate(category):
                commands.append((command, short_desc))
            commands.sort()

        # Compute the longest command
        max_cmd_size = max([len(cmd) for cmd,doc in commands])
        cmd_fmt = "<ansicyan>{0:<%d}</ansicyan>\t\t{1}" % max_cmd_size
        for cmd, doc in commands:
            if cmd != 'interactive':
                print_formatted_text(HTML(cmd_fmt.format(cmd, doc)))
        print('')
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

    def __init__(self, description: str = None, commands: bool=True, interface: bool=True, **kwargs):
        """Instanciate a CommandLineApp

        :param str program_name: program (app) name
        :param str usage: usage string
        :param str description: program description
        :param bool commands: if enabled, the application will consider first positional argument as a command
        :param bool interface: if enabled, the application will resolve a WHAD interface
        """
        super().__init__(description=description, **kwargs)

        self.__interface = None
        self.__input_iface = None
        self.__args = None
        self.__has_interface = interface
        self.__is_interface_piped = False
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
    def input_interface(self):
        """Input interface
        """
        return self.__input_iface

    @property
    def args(self):
        """Return the parsed arguments Namespace.
        """
        return self.__args

    def is_piped_interface(self):
        return self.__is_interface_piped

    def pre_run(self):
        """Prepare run for this application

        - parses arguments
        - handling color settings
        - resolve WHAD interface
        - handles piped interfaces
        """
        # First we need to parse the main arguments
        self.__args = self.parse_args()

        # If interface is provided, instantiate it and make it available
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

        # If no color is enabled, change color depth to 1 (black/white)
        if self.__args.nocolor:
            os.environ['PROMPT_TOOLKIT_COLOR_DEPTH']='DEPTH_1_BIT'

        # If stdout is piped, then tell prompt-toolkit to fallback to another
        # TTY (normally, stderr).
        if self.is_stdout_piped():
            get_app_session()._output = create_output(always_prefer_tty=True)

        # If stdin is piped, we must wait for a specific URL sent in a single
        # line that describes the interface to use.
        if self.is_stdin_piped():

            # Set stdin non-blocking
            orig_fl = fcntl.fcntl(sys.stdin, fcntl.F_GETFL)
            fcntl.fcntl(sys.stdin, fcntl.F_SETFL, orig_fl | os.O_NONBLOCK)

            # Wait an url on stdin to continue
            logger.debug('Stdin is piped, wait for a valid URL describing our interface.')
            pending_input = ''
            while True:
                # Check if something is available
                readers, _, errors = select.select([sys.stdin], [], [sys.stdin], .01)

                # Check if an error occurred.
                if len(errors) > 0:
                    # We're done
                    break

                # Read input from stdin
                if len(readers) > 0:
                    data_read = sys.stdin.read(4096)
                    if data_read == '' or data_read is None:
                        break

                    pending_input += data_read
                    # Check if we have a full line
                    if '\n' in pending_input:
                        idx = pending_input.index('\n')
                        line, pending_input = pending_input[:idx], pending_input[idx+1:]

                        # parse URL
                        url_info = urlparse(line)
                        if url_info.scheme == 'unix' and url_info.path is not None:
                            self.__interface_path = line
                            self.__is_interface_piped = True

                            # Create a Unix socket device and connect it to the
                            # given Unix socket path
                            self.__input_iface = UnixSocketDevice(url_info.path)
                            self.__input_iface.open()

                            # Copy parameters into our app parameters
                            params = dict(parse_qsl(url_info.query))
                            for param in params:
                                if not hasattr(self.args, param):
                                    setattr(self.args, param, params[param])

                            # We're done
                            break
                        else:
                            print(line)


    def post_run(self):
        """Implement post-run tasks.
        """
        # If stdout is piped, forward socket info to next tool
        if isinstance(self.__input_iface, UnixSocketDevice) and self.is_stdout_piped():
            sys.stdout.write('%s\n' % self.__interface_path)
            sys.stdout.flush()


    def run(self, pre=True, post=True):
        """Run the main application
        """
        # Launch pre-run tasks if required
        if pre:
            self.pre_run()

        # If we support first positional arg as command, parse the command
        if self.__has_commands:
            if self.__args.command is not None:
                command = self.__args.command
                handler = CommandsRegistry.get_handler(command)
                if handler is not None:
                    return handler(self, self.__args.command_args)
            elif CommandsRegistry.get_handler('interactive'):
                # If no command is passed to the CLI tool and an interactive
                # command handler has been defined, call it.
                handler = CommandsRegistry.get_handler('interactive')
                if handler is not None:
                    return handler(self, self.__args.command_args)                

            # By default, print help if no script is specified
            self.print_help()

        # Launch post-run tasks
        if post:
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
