"""RF4CE Network Layer (NWK) exceptions
"""

class NWKTimeoutException(Exception):
    """This exception is raised when a timeout occurs at NWK level.
    """
    def __init__(self):
        super().__init__()
