from whad.zigbee.stack.apl.zcl.exceptions import ZCLCommandNotFound

class ZCLCommand:
    """
    This class represents a Zigbee Cluster Library command.
    """
    def __init__(
                    self,
                    name,
                    generate_callback=None,
                    receive_callback=None
    ):
        self.name = name
        self.generate_callback = generate_callback
        self.receive_callback = receive_callback

class ZCLCommands:
    """
    This class represents a database of Zigbee Cluster Library commands.
    """
    def __init__(self):
        self.commands = {}

    def add_command(self, id, name, generate_callback=None, receive_callback=None):
        """
        Add a command in the command database.
        """
        self.commands[id] = ZCLCommand(
            name,
            generate_callback,
            receive_callback
        )

    def get_command_by_id(self, id):
        """
        Get a command from the database according to its identifier.
        """
        if id in self.commands:
            return self.commands[id]
        raise ZCLCommandNotFound()

    def get_command_by_callback(self, callback):
        """
        Get a command from the database according to one of its callbacks.
        """
        for command_id, command in self.commands.items():
            if (
                command.generate_callback == callback or
                command.receive_callback == callback
            ):
                return (command_id, command)
                
        raise ZCLCommandNotFound()
