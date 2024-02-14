"""
Exceptions linked to the ZigBee Cluster Library
"""

class ZCLAttributePermissionDenied(Exception):
    """
    Exception raised when permission to access an attribute is denied.
    """
    def __init__(self):
        super().__init__()

class ZCLAttributeNotFound(Exception):
    """
    Exception raised when an attribute is not found.
    """
    def __init__(self):
        super().__init__()

class ZCLCommandNotFound(Exception):
    """
    Exception raised when a command is not found.
    """
    def __init__(self):
        super().__init__()
