"""
WHAD exceptions
"""

class RequiredImplementation(Exception):
    """
    This exception is raised when a class does not provide any implementation
    for a specific method, usually in interface classes.
    """
    def __init__(self):
        super().__init__()


# Device discovery exceptions

class UnsupportedDomain(Exception):
    def __init__(self):
        super().__init__()


class UnsupportedCapability(Exception):
    def __init__(self, capability):
        super().__init__()
        self.__capability = capability

    @property
    def capability(self):
        return self.__capability

    def __str__(self):
        return 'UnsupportedCapability(%s)' % self.__capability

    def __repr__(self):
        return str(self)


# Device communication exceptions

class WhadDeviceNotReady(Exception):
    def __init__(self):
        super().__init__()

class WhadDeviceNotFound(Exception):
    def __init__(self):
        super().__init__()

class WhadDeviceAccessDenied(Exception):
    def __init__(self, device_name):
        self.__device_name = device_name
        super().__init__()

    def __str__(self):
        return 'WhadDeviceAccessDenied(%s) - missing udev rules' % self.__device_name

# External tools exceptions

class ExternalToolNotFound(Exception):
    def __init__(self, tool):
        super().__init__()
        self.__tool = tool

    def __str__(self):
        return 'ExternalToolNotFound(%s)' % self.__tool

    def __repr__(self):
        return str(self)

# Triggers exception
class TriggerNotAssociated(Exception):
    def __init__(self):
        super().__init__()

class InvalidTriggerPattern(Exception):
    def __init__(self):
        super().__init__()
