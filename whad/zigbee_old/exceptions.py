class MissingNetworkSecurityHeader(Exception):
    """
    Exception raised when no network security header can be found during encryption / decryption.
    """
    def __init__(self):
        super().__init__()

class Dot15d4TimeoutException(Exception):
    """
    Default exception raised when a wait for packet method reachs its timeout.
    """
    def __init__(self):
        super().__init__()
