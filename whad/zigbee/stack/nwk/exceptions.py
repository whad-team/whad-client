"""ZigBee Network Layer (NWK) exceptions
"""

class NWKTimeoutException(Exception):
    """This exception is raised when a timeout occurs at NWK level.
    """
    def __init__(self):
        super().__init__()

class NWKInvalidKey(Exception):
    """This exception is raised when the provided key is invalid.
    """
    def __init__(self):
        super().__init__()
