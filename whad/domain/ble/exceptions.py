class InvalidUUIDException(Exception):
    """Exception raised when an invalid UUID is used.
    """
    def __init__(self):
        super().__init__()

class InvalidBDAddressException(Exception):
    """Invalid BD address used
    """
    def __init__(self):
        super().__init__()

class InvalidHandleValueException(Exception):
    def __init__(self):
        super().__init__()

