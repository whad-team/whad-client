class MissingEncryptedKeystrokePayload(Exception):
    """
    Exception raised when no encrypted payload can be found during decryption.
    """
    def __init__(self):
        super().__init__()
