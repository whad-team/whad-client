from whad.zigbee.stack.apl.zcl.exceptions import ZCLCommandNotFound

class ZCLCommand:
    def __init__(self, name, generate_callback=None, receive_callback=None):
        self.name = name
        self.generate_callback = generate_callback
        self.receive_callback = receive_callback

class ZCLCommands:
    def __init__(self):
        self.commands = {}

    def add_command(self, id, name, generate_callback=None, receive_callback=None):
        self.commands[id] = ZCLCommand(name, generate_callback, receive_callback)
