"""WHAD CLI Interactive shell module
"""
import os
import re
import shlex
from prompt_toolkit import PromptSession, HTML, print_formatted_text
from prompt_toolkit.completion import NestedCompleter, DynamicCompleter
from whad.cli.ui import error, warning, success, info

class category(object):
    """Shell command handler decorator.

    This decorator adds a category to the command handler (do_<something>)
    that will be used to group commands in help menu.
    """

    def __init__(self, category: str):
        self.category = category

    def __call__(self, handler):
        handler.category = self.category
        return handler


class InteractiveShell(object):

    """Interactive shell for WHAD CLI applications.

    This class introduce a behavior similar to Python's `cmd` module:
     - each command is implemented in a `do_<command>` method
     - for each command, a `complete_<command>` method can be implemented to
       provide contextual parameter completion
     - exit/quit commands are automatically handled

    Commands are automatically documented through their respective docstrings,
    as shown below:

    ```
    do_something(self, args):
        '''Do something

        <ansicyan><b>something</b> <i>[ some param ]</i></ansicyan>

        This command does something.
        '''
        pass
    ```

    Docstrings can use prompt-toolkit HTML to add colors and effects.
    """

    def __init__(self, default_prompt='> '):
        self.__commands = {}
        self.__commands_ac = {}
        self.__categories = {}
        self.__prompt = default_prompt
        self.__quit = False
        self.__env = {}
        self.__session = None

        # Search specific commands named 'do_$command$'
        for member_name in dir(self):
            member = getattr(self, member_name)
            if callable(member) and member_name.startswith('do_'):
                # Found a do_* method
                command = member_name[3:]
                if len(command) >= 1:
                    # Associate command with method
                    self.__commands[command] = member

                    # Add category if defined
                    if hasattr(member, 'category'):
                        member_category = getattr(member, 'category')
                        if member_category not in self.__categories:
                            self.__categories[member_category] = []
                        self.__categories[member_category].append(command)

                    # Look for autocomplete method
                    if hasattr(self, 'complete_%s' % command):
                        command_ac = getattr(self, 'complete_%s' % command)
                        if callable(command_ac):
                            # Save autocomplete method
                            self.__commands_ac[command] = command_ac
                    else:
                        # No autocomplete found
                        self.__commands_ac[command] = None


    def set_prompt(self, prompt, force_update=False):
        """Set interactive shell prompt.

        :param str prompt: Prompt
        """
        self.__prompt = prompt
        if force_update and self.__session is not None:
            # We modify the `_message` attribute of our session
            # from the outside
            self.__session.message = self.__prompt

    def update_autocomplete(self):
        """Update nested autocompleter.

        This method will ask each command handler to autocomplete based on
        current state.
        """
        commands_autocomplete = {}
        for command in self.__commands_ac:
            if self.__commands_ac[command] is not None:
                nested_autocomplete = self.__commands_ac[command]()
                commands_autocomplete[command] = nested_autocomplete
            else:
                commands_autocomplete[command] = {}
        return NestedCompleter.from_nested_dict(commands_autocomplete)

    def autocomplete_env(self, pattern=None):
        """Return a list of current environment variables.

        :param str pattern: regular expression to filter variables
        """
        completions = {}
        for var in self.__env:
            if pattern is not None:
                if re.match(pattern, self.__env[var]):
                    completions['$'+var] = {}
            else:
                completions['$'+var] = {}
        return completions

    def process(self, input):
        """Process input commands.
        """
        try:
            # Dispatch commands
            tokens = shlex.split(input)
            if len(tokens) >= 1:
                command = tokens[0]
                if command in self.__commands:
                    resolved_args = [self.resolve(arg) for arg in tokens[1:]]
                    try:
                        # Command is supported, follow to method
                        return self.__commands[command](resolved_args)
                    except KeyboardInterrupt as kbd_int:
                        print('\rInterrupted by user.')
        except ValueError:
            self.warning('An error occurred while processing your command.')

    def run(self):
        """Run the interactive shell.
        """
        try:
            self.__session = PromptSession(completer=DynamicCompleter(self.update_autocomplete))
            while not self.__quit:
                input = self.__session.prompt(self.__prompt)
                res = self.process(input)
                if res:
                    break
        except KeyboardInterrupt as kbd:
            # Call do_quit() to terminate
            self.do_quit([])
        except EOFError as eof:
            # Call do_quit() to terminate
            self.do_quit([])

    def run_script(self, script_path):
        """Run a script

        :param str script_path: path to a script file
        """
        try:
            # run script
            commands = open(script_path,'r').readlines()
            for command in commands:
                res = self.process(command)
                if res:
                    break
        except IOError as ioerr:
            self.error('Cannot access script file "%s"' % script_path)

    def do_quit(self, args):
        """This method must be overriden to handle tool termination.
        """
        pass

    def stop(self):
        """Stop the interactive shell.
        """
        self.__quit = True

    def complete_help(self):
        """Auto-complete help command.
        """
        completions = {}
        for command in self.__commands:
            completions[command] = {}
        return completions

    def do_help(self, args):
        """show this help screen

        <ansicyan><b>help</b> <i>[ command ]</i></ansicyan>

        Shows help about the given command, if specified.
        """
        if len(args) >= 1:
            # Target command specified
            command = args[0]

            if command in self.__commands:
                # Get command docstring
                handler = self.__commands[command]
                if handler is not None and hasattr(handler, '__doc__'):
                    # Read docstring
                    docstr = getattr(handler,'__doc__')
                    desc = '\n'.join([l.lstrip() for l in docstr.splitlines()[1:]])
                    print_formatted_text(HTML(desc.strip()))
                    print('')
                else:
                    self.warning('command <u>%s</u> is not documented' % command)
            else:
                self.error('command <u>%s</u> does not exist.' % command)
        else:
            max_cmd_size = max([len(cmd) for cmd in list(self.__commands.keys())])

            # List available commands, categories first and then uncategorized.
            categorized_commands = []
            for category in self.__categories:
                commands = []
                for command in self.__categories[category]:
                    # Get command docstring
                    handler = self.__commands[command]
                    if handler is not None and hasattr(handler, '__doc__'):
                        # Read docstring
                        docstr = getattr(handler,'__doc__')
                        short_desc = docstr.splitlines()[0].lstrip()
                    else:
                        short_desc = ''
                    commands.append((command, short_desc))
                    categorized_commands.append(command)

                # Show commands
                print_formatted_text(HTML('<ansimagenta><b>%s:</b></ansimagenta>' % category))
                #max_cmd_size = max([len(cmd) for cmd,doc in commands])
                cmd_fmt = "  <ansicyan>{0:<%d}</ansicyan>\t\t{1}" % max_cmd_size
                for cmd, doc in commands:
                    print_formatted_text(HTML(cmd_fmt.format(cmd, doc)))
                print('')

            commands = []
            for command in self.__commands:
                if command not in categorized_commands:
                    # Get command docstring
                    handler = self.__commands[command]
                    if handler is not None and hasattr(handler, '__doc__'):
                        # Read docstring
                        docstr = getattr(handler,'__doc__')
                        short_desc = docstr.splitlines()[0].lstrip()
                    else:
                        short_desc = ''
                    commands.append((command, short_desc))

            # Show commands
            print_formatted_text(HTML('<ansimagenta><b>Generic commands:</b></ansimagenta>'))
            #max_cmd_size = max([len(cmd) for cmd,doc in commands])
            cmd_fmt = "  <ansicyan>{0:<%d}</ansicyan>\t\t{1}" % max_cmd_size
            for cmd, doc in commands:
                print_formatted_text(HTML(cmd_fmt.format(cmd, doc)))


    def resolve(self, arg):
        """Resolve a shell parameter.

        This method checks if parameter is an environment variable and replace
        it with its value, or return the original parameter.

        :param str arg: shell parameter to resolve
        :return str: resolved parameter
        """
        if arg.startswith('$'):
            if arg[1:] in self.__env:
                return self.__env[arg[1:]]
            else:
                return arg
        elif arg.startswith('\\$'):
            return arg[1:]
        else:
            return arg

    def do_set(self, args):
        """set environment variable

        <ansicyan><b>set</b> <i>ENV_VAR</i> <i>value</i></ansicyan>

        Set <i>ENV_VAR</i> environment variable to <i>value</i> and keep it in
        memory for the current session. This variable can be recalled with the
        following notation: <i>$ENV_VAR</i>.

        Variable's name cannot include digits, and only '_' is allowed as special
        char.
        """
        if len(args)>=2:
            varname = args[0]
            varval = args[1]

            # make sure name matches requirements
            if re.match('^[a-zA-Z_]+$', varname):
                # Store variable in environment
                self.__env[varname] = self.resolve(varval)
            else:
                self.error('Variable name contains an invalid character')
        else:
            self.error('Missing argument (see help)')

    def do_env(self, args):
        """show environment variables

        <ansicyan><b>env</b></ansicyan>

        List environment variables.
        """
        for var in self.__env:
            print_formatted_text(HTML('<ansicyan>%s</ansicyan>=%s' % (
                var, self.__env[var]
            )))

    def do_unset(self, args):
        """remove environment variable

        <ansicyan><b>unset</b> <i>VAR_NAME</i></ansicyan>

        Remove <i>VAR_NAME</i> from environment.
        """
        if len(args)>=1:
            varname = args[0]
            if varname in self.__env:
                del self.__env[varname]

    def do_wait(self, args):
        """show a message and wait for the user to press a key

        <ansicyan><b>wait</b> <i>[MESSAGE]</i></ansicyan>

        Display <i>MESSAGE</i> in the standard output and wait for
        the user to press ENTER.

        If message is not provided, use a default message.
        """
        if len(args)>=1:
            message = args[0]
        else:
            message = "Press ENTER to continue..."

        # Show message and wait for a keypress
        try:
            print_formatted_text(HTML('<i>%s</i>' % message))
            input()
        except EOFError:
            self.warning("Cannot wait for keyboard input, is your stdin piped to another app ?")

    def do_echo(self, args):
        """Display a text in the standard output.

        <ansicyan><b>echo</b> <i>TEXT</i></ansicyan>

        Print <i>TEXT</i> to the standard output.
        """
        if len(args)>=1:
            print(args[0])


    def success(self, message):
        """Display a success message in green (if color is enabled)
        """
        success(message)

    def warning(self, message):
        """Display a warning message in orange (if color is enabled)
        """
        warning(message)

    def error(self, message):
        """Display an error message in red (if color is enabled)
        """
        error(message)



if __name__ == '__main__':
    class MyShell(InteractiveShell):
        def __init__(self):
            super().__init__('> ')

        def complete_test(self):
            return {'this':None, 'that':None}

        def do_test(self, args):
            print(args)

    ishell = MyShell()
    ishell.run()
