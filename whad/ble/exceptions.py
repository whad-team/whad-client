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


class InvalidHandleValueException(Exception):
    def __init__(self):
        super().__init__()


class InvalidAccessAddressException(Exception):
    def __init__(self):
        super().__init__()


################################
# Connection related exceptions
################################

class PeripheralNotFound(Exception):
    """This exception is raised when a targeted peripheral cannot be found.
    """
    def __init__(self, peripheral=None):
        super().__init__()
        self.peripheral = peripheral

class NotConnected(Exception):
    """This exception is raised when a peripheral is used while not connected.
    """
    def __init__(self, peripheral=None):
        super().__init__()
        self.peripheral = peripheral

class NotSynchronized(Exception):
    """This exception is raised when a connection is used while not synchronized.
    """
    def __init__(self):
        super().__init__()

    def __repr__(self):
        return "NotSynchronized"
        
class ConnectionLostException(Exception):
    """This exception is raised when a connection is unexpectedly terminated.
    """
    def __init__(self, connection=None):
        super().__init__()
        self.connection = connection


#######################
# Hook Exceptions
#######################

class HookDontForward(Exception):
    """Raise this exception in a hook to avoid forwarding.
    """

    def __init__(self):
        super().__init__()

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


class HookReturnAuthentRequired(Exception):
    """Raise this exception in a hook to ask for authentication.
    """

    def __init__(self):
        super().__init__()


class HookReturnAuthorRequired(Exception):
    """Raise this exception in a hook to notify an Authorization is required
    to access an attribute.
    """

    def __init__(self):
        super().__init__()

#######################
#Crypto Exceptions
#######################

class MissingCryptographicMaterial(Exception):
    """Raise this exception if a decryption is attempted without having cryptographic material available.
    """

    def __init__(self):
        super().__init__()
