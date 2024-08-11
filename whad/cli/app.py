"""Command-line interface application module

This module provides multiple classes to create compatible CLI tools:
- CommandLineSource
- CommandLineSink
- CommandLinePipe
- CommandLineDeviceSource
- CommandLineDeviceSink
- CommandLineDevicePipe

Standard command-line application classes
-----------------------------------------

Basically, a `CommandLineSource` application can see its standard output tied
to a `CommandLineSink` or  `CommandLinePipe` application, while a  `CommandLineSink`
application can see its standard input fed by a `CommandLineSink` or a
`CommandLinePipe` application. Chosing the right class for an application is
critical because our CLI framework performs some checks and does not allow
for instance a `CommandLineSource` application to see its standard input fed
with another command-line tool.

Generally, applications providing an interactive shell are based on the
`CommandLineSource` application class, as the user is expected to type
commands and to interact with the application's interactive shell.

The following schemes are then possible:

- [CommandLineSource] | [CommandLineSink]
- [CommandLineSource] | [CommandLinePipe] | [CommandLineSink]


WHAD-based command-line application classes
-------------------------------------------

WHAD offers the possibility to chain different tools to create flexible packet
processing flows. This is automatically handled by our CLI device-based application
classes.

An application using the `CommandLineDeviceSource` class will therefore be in
charge of configuring a WHAD adapter specified with the `--interface` option,
perform some actions and then allow a chained tool to take control of this
adapter to perform other actions.

An application using the `CommandLineDeviceSink` class is supposed to get
messages from the previous tool and process them before sending them to a
specific device handled by this application itself. Everything is automated
by our CLI framework and the application's `input_interface` property does
expose the input interface the application is connected to.

Last but not least, an application using the `CommandLineDevicePipe` class will
process every incoming message and forward them (or not) to a chained tool.

"""
import os
import sys
import select
import fcntl
import logging
import traceback

from typing import Generator
from urllib.parse import urlparse, parse_qsl
from signal import signal, SIGPIPE, SIG_DFL
from argparse import ArgumentParser

from prompt_toolkit import print_formatted_text, HTML
from prompt_toolkit.output import create_output
from prompt_toolkit.application.current import get_app_session


from whad.device import WhadDevice, UnixSocketDevice
from whad.exceptions import WhadDeviceAccessDenied, WhadDeviceNotFound, \
    WhadDeviceNotReady, WhadDeviceTimeout, UnsupportedDomain

logger = logging.getLogger(__name__)

signal(SIGPIPE,SIG_DFL)

# Python logging level aliases
LOGLEVEL_ALIASES = {
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'info': logging.INFO,
    'debug': logging.DEBUG
}

class ApplicationError(Exception):
    """Application error
    """
    def __init__(self, reason: str):
        """Initialize an application error.
        """
        super().__init__()
        self.__reason = reason

    def show(self):
        """Show the exception in terminal
        """
        print_formatted_text(HTML(f"<ansired>[!] <b>{self.__reason}</b></ansired>"))

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
    def register(name: str, handler, category: str):
        """Register a command
        """
        # Add command to our list of known commands
        CommandsRegistry.COMMANDS[name] = handler

        # Add command to the corresponding category
        if category not in CommandsRegistry.CATEGORIES:
            CommandsRegistry.CATEGORIES[category] = []
        CommandsRegistry.CATEGORIES[category].append(name)

        # Extract short desc and description from docstring
        if hasattr(handler, '__doc__'):
            docstr = getattr(handler, '__doc__')
            short_desc = docstr.splitlines()[0].lstrip()
            desc = '\n'.join([l.lstrip() for l in docstr.splitlines()[1:]])
        else:
            short_desc = ''
            desc = ''

        if short_desc is not None:
            CommandsRegistry.CMDS_SHORT_DESC[name] = short_desc
        if desc is not None:
            CommandsRegistry.CMDS_DESC[name] = desc

    @staticmethod
    def get_handler(command_name: str):
        """Get command handler from command name.

        :param command_name: Command name
        :type command_name: str
        :return: function associated with the command or None if none registered
        """
        if command_name in CommandsRegistry.COMMANDS:
            return CommandsRegistry.COMMANDS[command_name]
        else:
            return None

    @staticmethod
    def get_short_desc(command_name: str) -> str:
        """Get command short description from command name.

        :param command_name: Command name
        :type command_name: str
        :return: Short description associated with the command or None if none registered
        """
        if command_name in CommandsRegistry.CMDS_SHORT_DESC:
            return CommandsRegistry.CMDS_SHORT_DESC[command_name]
        else:
            return None

    @staticmethod
    def get_desc(command_name: str):
        """Get command long description from command name.

        :param command_name: Command name
        :type command_name: str
        :return: Long description associated with the command or None if none registered
        """
        if command_name in CommandsRegistry.CMDS_DESC:
            return CommandsRegistry.CMDS_DESC[command_name]
        else:
            return None

    @staticmethod
    def enumerate_categories() -> Generator[str, None, None]:
        """Enumerate over command categories
        """
        for category in CommandsRegistry.CATEGORIES:
            yield category

    @staticmethod
    def enumerate(category=None) -> Generator[tuple, None, None]:
        """Enumerate over all categories or one specific, if provided.

        :param category: Category to iterate
        :type category: str
        """
        if category is None:
            for cmd_name in CommandsRegistry.COMMANDS:
                yield (
                    cmd_name,
                    CommandsRegistry.get_short_desc(cmd_name),
                    CommandsRegistry.get_desc(cmd_name)
                )
        else:
            for cmd_name in CommandsRegistry.COMMANDS:
                if cmd_name in CommandsRegistry.CATEGORIES[category]:
                    yield (
                        cmd_name,
                        CommandsRegistry.get_short_desc(cmd_name),
                        CommandsRegistry.get_desc(cmd_name)
                    )


@command('help')
def show_default_help(_, args):
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
    # WHAD interface related errors
    DEV_READY = 0
    DEV_NOT_FOUND_ERR = -1
    DEV_NOT_READY_ERR = -2
    DEV_ACCESS_ERR = -3

    # Application input types (when piped)
    INPUT_NONE = 0
    INPUT_STANDARD = 1
    INPUT_WHAD = 2

    # Application output types (when piped)
    OUTPUT_NONE = 0
    OUTPUT_STANDARD = 1
    OUTPUT_WHAD = 2

    def __init__(self, description: str = None, commands: bool=True, interface: bool=True, input: int = INPUT_WHAD,
                 output: int = OUTPUT_WHAD, **kwargs):
        """Instanciate a CommandLineApp

        :param str program_name: program (app) name
        :param str usage: usage string
        :param str description: program description
        :param bool commands: if enabled, the application will consider first positional argument as a command
        :param bool interface: if enabled, the application will resolve a WHAD interface
        :param int input: specify the input type when application has its stdin piped
        :param int output: specify the output type when application has its stdout piped
        """
        super().__init__(description=description, **kwargs)

        self.__interface = None
        self.__input_iface = None
        self.__input_type = input
        self.__output_type = output
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

        # Add our default option --no-colorfself
        self.add_argument(
            '--no-color',
            dest='nocolor',
            action='store_true',
            default=False,
            help='disable colors in output'
        )

        # Add our default option --log
        # (-l option not available, we must keep with the long name)
        self.add_argument(
            '--log',
            dest='loglevel',
            choices=['error', 'warn', 'info', 'debug'],
            default=None,
            help='set the logging level for this application'
        )

        # Logfile (-f option not available, we must keep with the long name)
        self.add_argument(
            '--log-file',
            dest='logfile',
            metavar='LOGFILE_PATH',
            default=None,
            help='write the log output into LOGFILE_PATH'
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


    @interface.setter
    def interface(self, iface):
        """Sets the selected WHAD interface.
        """
        self.__interface = iface

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
        """Determine if the input interface is piped from a previous app in
        the command line
        """
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

        # Handle debug options if provided
        if self.__args.loglevel is not None:
            # Convert level to corresponding Python logging level
            desired_level = LOGLEVEL_ALIASES[self.__args.loglevel]

            # Shall we log into a specific file ?
            if self.__args.logfile is not None:
                try:
                    logging.basicConfig(filename=self.__args.logfile,
                                        level=desired_level)
                except IOError:
                    self.error(
                        f'Specified log output file ({self.__args.logfile}) cannot be accessed, falling back to stderr.'
                    )
                    logging.basicConfig(level=desired_level)
            else:
                # Else we log into stderr
                logging.basicConfig(level=desired_level)

        # If no color is enabled, change color depth to 1 (black/white)
        if self.__args.nocolor:
            os.environ['PROMPT_TOOLKIT_COLOR_DEPTH']='DEPTH_1_BIT'

        # If interface is provided, instantiate it and make it available
        if self.__has_interface:
            if self.__args.interface is not None:
                try:
                    # Create WHAD interface
                    self.__interface = WhadDevice.create(self.__args.interface)
                except WhadDeviceNotFound as dev_404:
                    raise ApplicationError(f"Whad adapter '{self.__args.interface}' not found.") from dev_404
                except WhadDeviceAccessDenied as dev_403:
                    raise ApplicationError("Cannot access WHAD device, please check permissions.") from dev_403
                except WhadDeviceNotReady as dev_500:
                    raise ApplicationError("WHAD device is not ready.") from dev_500

        # If stdout is piped, then tell prompt-toolkit to fallback to another
        # TTY (normally, stderr).
        if self.is_stdout_piped():
            # Check if this application is supposed to be chained to another app
            if self.__output_type != CommandLineApp.OUTPUT_NONE:
                get_app_session()._output = create_output(always_prefer_tty=True)
            else:
                logger.error("This application (%s) cannot be piped with another tool.", self.prog)
                sys.exit(2)

        # If application stdin is piped, we have two possibilities:
        # - the application is supposed to handle "normal" data from stdin
        # - the application is supposed to be chained with another WHAD CLI tool
        if self.is_stdin_piped():
            self.__input_iface = None
            # If stdin is piped to a WHAD tool, we must wait for a specific URL
            # sent in a single line that describes the interface to use.
            if self.__input_type == CommandLineApp.INPUT_WHAD:

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
                                for param, value in params.items():
                                    if not hasattr(self.args, param):
                                        setattr(self.args, param, value)

                                # We're done
                                break
                            else:
                                # If stdout is not piped, print line
                                if not self.is_stdout_piped():
                                    print(line)
            else:
                # Check if this application is supposed to be chained with
                # another app and to process its standard input
                if self.__input_type == CommandLineApp.INPUT_NONE:
                    logger.error(
                        "This application (%s) cannot be piped with another tool.",
                        self.prog
                    )
                    sys.exit(2)

        # If we have no WHAD adapter specified then that's abnormal.
        elif self.__interface is None and self.__has_interface:
            raise ApplicationError("You must select a WHAD adapter with the --interface option.")


    def post_run(self):
        """Implement post-run tasks.
        """
        if self.__output_type == CommandLineApp.OUTPUT_WHAD:
            # If stdout is piped, forward socket info to next tool
            if isinstance(self.__input_iface, UnixSocketDevice) and self.is_stdout_piped():
                sys.stdout.write('%s\n' % self.__interface_path)
                sys.stdout.flush()
        elif self.__input_type == CommandLineApp.INPUT_WHAD and self.__input_iface is not None:
            # if stdin is piped, close unix socket
            self.__input_iface.close()


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

    def readline_from_stdin(self):
        """Reads a line from stdin when application has its stdin piped

        :return str: line read from stdin
        """
        pending_input = ''
        while True:
            data_read = sys.stdin.read(4096)
            if data_read == '' or data_read is None:
                break
        return pending_input

    def warning(self, message):
        """Display a warning message in orange (if color is enabled)
        """
        try:
            print_formatted_text(HTML('<aaa fg="#e97f11">/!\\ <b>%s</b></aaa>' % message))
        except:
            print_formatted_text(HTML('<aaa fg="#e97f11">/!\\ <b>%s</b></aaa>' % 'an unknown warning occured'))

    def error(self, message):
        """Display an error message in red (if color is enabled)
        """
        try:
            print_formatted_text(HTML('<ansired>[!] <b>{message}</b></ansired>').format(message=message))
        except Exception as err:
            logger.error('[!] an unknown error occured: %s',err)


class CommandLineSource(CommandLineApp):
    """
    Command-line application that can send data to standard output.
    """
    def __init__(self, description: str = None, commands: bool=True, interface: bool=True, **kwargs):
        """Create a command-line application object that supports no standard input processing
        and is able to send data to standard output for tool chaining.

        :param str description: program description
        :param bool commands: if enabled, the application will consider first positional argument as a command
        :param bool interface: if enabled, the application will resolve a WHAD interface
        """
        super().__init__(description, commands, interface, CommandLineApp.INPUT_NONE, CommandLineApp.OUTPUT_STANDARD, **kwargs)


class CommandLineSink(CommandLineApp):
    """
    Command-line application that can read data from standard input.
    """
    def __init__(self, description: str = None, commands: bool=True, interface: bool=True, **kwargs):
        """Create a command-line application object that only supports standard input processing
        and cannot be chained with another tool.

        :param str description: program description
        :param bool commands: if enabled, the application will consider first positional argument as a command
        :param bool interface: if enabled, the application will resolve a WHAD interface
        """
        super().__init__(description, commands, interface, CommandLineApp.INPUT_STANDARD, CommandLineApp.OUTPUT_NONE, **kwargs)

class CommandLinePipe(CommandLineApp):
    """
    Command-line application that reads data from standard input and send data
    to standard output.
    """

    def __init__(self, description: str = None, commands: bool=True, interface: bool=True, **kwargs):
        """Create a command-line application object that supports standard input processing
        and is able to send data to standard output for tool chaining.

        :param str description: program description
        :param bool commands: if enabled, the application will consider first positional argument as a command
        :param bool interface: if enabled, the application will resolve a WHAD interface
        """
        super().__init__(description, commands, interface, CommandLineApp.INPUT_STANDARD, CommandLineApp.OUTPUT_STANDARD, **kwargs)

class CommandLineDeviceSource(CommandLineApp):
    """
    Command-line application that can be chained with a `CommandLineDeviceSink` or `CommandLineDevicePipe` application,
    in a timely manner.
    """

    def __init__(self, description: str = None, commands: bool=True, interface: bool=True, **kwargs):
        """Create a command-line application object that supports no standard input processing
        and is able to send data to standard output for tool chaining.

        :param str description: program description
        :param bool commands: if enabled, the application will consider first positional argument as a command
        :param bool interface: if enabled, the application will resolve a WHAD interface
        """
        super().__init__(description, commands, interface, CommandLineApp.INPUT_NONE, CommandLineApp.OUTPUT_WHAD, **kwargs)


class CommandLineDeviceSink(CommandLineApp):
    """
    Command-line application that can receive WHAD messages from a chained source/pipe but cannot be
    chained with another application.
    """

    def __init__(self, description: str = None, commands: bool=True, interface: bool=True, **kwargs):
        """Create a command-line application object that only supports standard input processing
        and cannot be chained with another tool.

        :param str description: program description
        :param bool commands: if enabled, the application will consider first positional argument as a command
        :param bool interface: if enabled, the application will resolve a WHAD interface
        """
        super().__init__(description, commands, interface, CommandLineApp.INPUT_WHAD, CommandLineApp.OUTPUT_NONE, **kwargs)

class CommandLineDevicePipe(CommandLineApp):
    """
    Command-line application that handles/processes WHAD messages between two WHAD command-line applications.
    """

    def __init__(self, description: str = None, commands: bool=True, interface: bool=True, **kwargs):
        """Create a command-line application object that supports standard input processing
        and is able to send data to standard output for tool chaining.

        :param str description: program description
        :param bool commands: if enabled, the application will consider first positional argument as a command
        :param bool interface: if enabled, the application will resolve a WHAD interface
        """
        super().__init__(description, commands, interface, CommandLineApp.INPUT_WHAD, CommandLineApp.OUTPUT_WHAD, **kwargs)

def run_app(application: CommandLineApp):
    """Run an application and handle generic exceptions.
    """
    try:
        application.run()
    except ApplicationError as err:
        # If an error occured, display it.
        err.show()
    except KeyboardInterrupt:
        application.warning("Interrupted by user (CTL-C)")
    except WhadDeviceTimeout:
        application.error("WHAD adapter has timed out.")
    except WhadDeviceAccessDenied:
        application.error("Cannot access WHAD adapter, check permissions.")
    except UnsupportedDomain as domain_err:
        application.error("WHAD adapter does not support %s." % domain_err.domain)
    except Exception as exc:
        application.error("An unexpected exception occured:")
        traceback.print_exception(exc)

if __name__ == '__main__':

    @command('test', 'this is a small test command', 'detailed desc')
    def test_handler(_, args):
        """Handle test command
        """
        print(f"this is a test with args: {args}")

    app = CommandLineApp(description='Whad CLI demo')
    app.run()
