class MissingNetworkSecurityHeader(Exception):
    """
    Exception raised when no network security header can be found during encryption / decryption.
    """
    def __init__(self):
        super().__init__()
