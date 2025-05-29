"""
WHAD exceptions
"""

class RequiredImplementation(Exception):
    """
    This exception is raised when a class does not provide any implementation
    for a specific method, usually in interface classes.
    """


# Device discovery exceptions

class UnsupportedDomain(Exception):
    """
    Exception raised when a requested domain is not supported by a WHAD
    interface.
    """
    def __init__(self, domain: str):
        super().__init__()
        self.__domain = domain

    @property
    def domain(self):
        """Return the requested (and unsuppoted) domain name.
        """
        return self.__domain

    def __str__(self):
        """String representation.
        """
        return f"UnsupportedDomain({self.__domain})"

    def __repr__(self):
        """Python representation.
        """
        return str(self)

class UnsupportedCapability(Exception):
    """
    Exception raised when a specific requested capability is not supported by
    a WHAD interface.
    """

    def __init__(self, capability):
        super().__init__()
        self.__capability = capability

    @property
    def capability(self):
        """Return the unsupported capability.
        """
        return self.__capability

    def __str__(self):
        return f"UnsupportedCapability({self.__capability})"

    def __repr__(self):
        return str(self)


# Device communication exceptions

class WhadDeviceDisconnected(Exception):
    """
    Exception raised when a WHAD interface has disconnected.
    """

class WhadDeviceNotReady(Exception):
    """
    Exception raised when a WHAD interface is present but does not respond
    as expected.
    """

class WhadDeviceNotFound(Exception):
    """
    Raised when a specified WHAD interface has not been found.
    """

class WhadDeviceAccessDenied(Exception):
    """
    Exception raised when a WHAD interface cannot be accessed due to wrong
    permissions.
    """

    def __init__(self, device_name):
        self.__device_name = device_name
        super().__init__()

    def __str__(self):
        return f"WhadDeviceAccessDenied({self.__device_name}) - missing udev rules"

class WhadDeviceUnsupportedOperation(Exception):
    """
    Exception is raised when a specific requested operation is not supported by
    the WHAD interface.
    """

    def __init__(self, operation, message):
        self.__operation = operation
        self.__message = message

    def __str__(self):
        return f"WhadDeviceUnsupportedOperation({self.__operation}) - {self.__message}"

    def __repr__(self):
        return str(self)

class WhadDeviceTimeout(Exception):
    """
    Excepton raised when a WHAD interface communication timed out.
    """

    def __init__(self, message):
        self.__message = message

    def __str__(self):
        return f"WhadDeviceTimeout({self.__message})"

class WhadDeviceError(Exception):
    """
    Exception is raised when an error occurred during WHAD interface management.
    """

    def __init__(self, message):
        self.__message = message

    def __str__(self):
        return f"WhadDeviceError({self.__message})"
    
    @property
    def message(self) -> str:
        return self.__message

# External tools exceptions

class ExternalToolNotFound(Exception):
    """
    Exception is raised when an external tool cannot be found.
    """

    def __init__(self, tool):
        super().__init__()
        self.__tool = tool

    def __str__(self):
        return f"ExternalToolNotFound({self.__tool})"

    def __repr__(self):
        return str(self)

# Triggers exception
class TriggerNotAssociated(Exception):
    """
    Exception is raised when a trigger cannot be found.
    """

class InvalidTriggerPattern(Exception):
    """
    Exception is raised when a provided trigger pattern is invalid.
    """

# Generic replay
class ReplayInvalidRole(Exception):
    """
    Exception raised when an invalid role has been selected regarding a requested
    operation.
    """

    def __repr__(self):
        return "ReplayInvalidRole"
