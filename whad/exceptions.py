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


class ResultUnsupportedDomain(Exception):
    def __init__(self):
        super().__init__()
