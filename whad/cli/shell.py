"""WHAD CLI Interactive shell module
"""
import os
from prompt_toolkit import PromptSession, HTML, print_formatted_text
from prompt_toolkit.completion import NestedCompleter, DynamicCompleter

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
        self.__prompt = default_prompt
        self.__quit = False

        # Search specific commands named 'do_$command$'
        for member_name in dir(self):
            member = getattr(self, member_name)
            if callable(member) and member_name.startswith('do_'):
                # Found a do_* method
                command = member_name[3:]
                if len(command) >= 1:
                    # Associate command with method
                    self.__commands[command] = member

                    # Look for autocomplete method
                    if hasattr(self, 'complete_%s' % command):
                        command_ac = getattr(self, 'complete_%s' % command)
                        if callable(command_ac):
                            # Save autocomplete method
                            self.__commands_ac[command] = command_ac
                    else:
                        # No autocomplete found
                        self.__commands_ac[command] = None

        self.__session = PromptSession(completer=DynamicCompleter(self.update_autocomplete))


    def set_prompt(self, prompt):
        """Set interactive shell prompt.

        :param str prompt: Prompt
        """
        self.__prompt = prompt


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

    def process(self, input):
        """Process input commands.
        """
        # Dispatch commands
        command = input.split(' ')[0]
        if command in self.__commands:
            # Command is supported, follow to method
            return self.__commands[command]([arg for arg in input.split(' ')[1:] if arg != ''])

    def run(self):
        """Run the interactive shell.
        """
        while not self.__quit:
            input = self.__session.prompt(self.__prompt)
            res = self.process(input)
            if res:
                break

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
                else:
                    self.warning('command <u>%s</u> is not documented' % command)
            else:
                self.error('command <u>%s</u> does not exist.' % command)
        else:
            # List available commands
            commands = []
            for command in self.__commands:
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
            max_cmd_size = max([len(cmd) for cmd,doc in commands])
            cmd_fmt = "<ansicyan>{0:<%d}</ansicyan>\t\t{1}" % max_cmd_size
            for cmd, doc in commands:
                print_formatted_text(HTML(cmd_fmt.format(cmd, doc)))


    def warning(self, message):
        """Display a warning message in orange (if color is enabled)
        """
        print_formatted_text(HTML('<aaa fg="#e97f11">/!\\ <b>%s</b></aaa>' % message))

    def error(self, message):
        """Display an error message in red (if color is enabled)
        """
        print_formatted_text(HTML('<ansired>[!] <b>%s</b></ansired>' % message))



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