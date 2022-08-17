"""Bluetooth Low Energy domain exceptions
"""

class InvalidSerialPortException(Exception):
    """Exception raised whan an invalid serial port is provided
    """
    def __init__(self):
        super().__init()

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

#######################
# Hook Exceptions
#######################

class HookReturnValue(Exception):
    """Raise this exception in a hook to return a specific value to the
    caller.
    """
    
    def __init__(self, value):
        super().__init__()
        self.__value = value

    @property
    def value(self):
        return self.__value

class HookReturnGattError(Exception):
    """Raise this exception in a hook to return a GATT error.
    """

    def __init__(self, request, handle, error):
        """Create a HookReturnGattError with request, handle and error code specified.

        :param int request: GATT request
        :param int handle: GATT handle
        :param int error: Error code (from BleAttErrorCode)
        """
        super().__init__()
        self.__request = request
        self.__handle = handle
        self.__error = error

    @property
    def request(self):
        return self.__request

    @property
    def handle(self):
        return self.__handle

    @property
    def error(self):
        return self.__error


class HookReturnNotFound(Exception):
    """Raise this exception in a hook to indicate the requested object has not
    been found.
    """

    def __init__(self):
        super().__init__()

class HookReturnAccessDenied(Exception):
    """Raise this exception in a hook to return an error (access not allowed)
    """

    def __init__(self):
        super().__init__()


class HookReturnAuthRequired(Exception):
    """Raise this exception in a hook to ask for authentication.
    """

    def __init__(self):
        super().__init__()

