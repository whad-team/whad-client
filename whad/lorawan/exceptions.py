"""LoRaWAN exceptions
"""

class ChannelNotFound(Exception):
    """This exception is raised when no channel can be found for
    uplink or downlink, from the current frequency plan.
    """
    def __init__(self):
        super().__init__()


class InvalidDataRate(Exception):
    """This exception is raised when a required datarate does not
    correspond to one of the datarates available in the channel
    plan.
    """
    def __init__(self):
        super().__init__()

class NotStartedException(Exception):
    def __init__(self):
        super().__init__()

class BadEuiFormat(Exception):
    def __init__(self):
        super().__init__()

class BadMICError(Exception):
    def __init__(self):
        super().__init__()

class MissingKeyError(Exception):
    def __init__(self, keyname):
        super().__init__()
        self.keyname = keyname

    def __repr__(self):
        return 'MissingKeyError(%s)' % self.keyname
    
class InvalidNodeRegistryError(Exception):
    def __init__(self, registry_path):
        self.registry_path = registry_path

    def __repr__(self):
        return 'InvalidNodeRegistryError(path="%s")' % self.registry_path