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