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


class UnsupportedDomain(Exception):
    def __init__(self):
        super().__init__()


class UnsupportedCapability(Exception):
    def __init__(self, capability):
        super().__init__()
        self.__capability = capability

    def __str__(self):
        return 'UnsupportedCapability(%s)' % self.__capability

    def __repr__(self):
        return str(self)

class WhadDeviceNotReady(Exception):
    def __init__(self):
        super().__init__()

class WhadDeviceNotFound(Exception):
    def __init__(self):
        super().__init__()