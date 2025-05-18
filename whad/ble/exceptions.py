"""Bluetooth Low Energy domain exceptions
"""

class InvalidSerialPortException(Exception):
    """Exception raised whan an invalid serial port is provided
    """

class InvalidUUIDException(Exception):
    """Exception raised when an invalid UUID is used.
    """


class InvalidHandleValueException(Exception):
    """Exception raised when an invalid handle value is used.
    """


class InvalidAccessAddressException(Exception):
    """Exception raised when an invalid access address is used.
    """


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

class HookReturnValue(Exception):
    """Raise this exception in a hook to return a specific value to the
    caller.
    """

    def __init__(self, value: bytes):
        super().__init__()
        self.__value = value

    @property
    def value(self) -> bytes:
        """Return value
        """
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
        """Corresponding GATT request
        """
        return self.__request

    @property
    def handle(self) -> int:
        """Related attribute GATT handle value
        """
        return self.__handle

    @property
    def error(self) -> int:
        """Error code
        """
        return self.__error


class HookReturnNotFound(Exception):
    """Raise this exception in a hook to indicate the requested object has not
    been found.
    """

class HookReturnAccessDenied(Exception):
    """Raise this exception in a hook to return an error (access not allowed)
    """


class HookReturnAuthentRequired(Exception):
    """Raise this exception in a hook to ask for authentication.
    """


class HookReturnAuthorRequired(Exception):
    """Raise this exception in a hook to notify an Authorization is required
    to access an attribute.
    """

#######################
#Crypto Exceptions
#######################

class MissingCryptographicMaterial(Exception):
    """Raise this exception if a decryption is attempted without having
    cryptographic material available.
    """
