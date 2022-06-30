class InvalidUUIDException(Exception):
    """Exception raised when an invalid UUID is used.
    """
    def __init__(self):
        super().__init__()

class InvalidHandleValueException(Exception):
    """Exception raised when an invalid handle value is provided.
    """
    def __init__(self):
        super().__init__()
