class Dot15d4TimeoutException(Exception):
    """
    Default exception raised when a wait for packet method reachs its timeout.
    """
    def __init__(self):
        super().__init__()

class InvalidDot15d4AddressException(Exception):
    """
    Default exception raised when an invalid 802.15.4 address or Pan ID is provided.
    """
    def __init__(self):
        super().__init__()
        
