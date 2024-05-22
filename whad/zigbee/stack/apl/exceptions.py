"""ZigBee Applicative Layer (APL) exceptions
"""


class APLTimeoutException(Exception):
    """
    This exception is triggered when a timeout occured at the APL layer.
    """
    def __init__(self):
        super().__init__()

class APLInvalidAddress(Exception):
    """
    This exception is triggered when an invalid address is detected.
    """
    def __init__(self):
        super().__init__()
