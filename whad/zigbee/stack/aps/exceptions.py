"""ZigBee Application Sub Layer (NWK) exceptions
"""

class APSTimeoutException(Exception):
    """This exception is raised when a timeout occurs at APS level.
    """
    def __init__(self):
        super().__init__()
