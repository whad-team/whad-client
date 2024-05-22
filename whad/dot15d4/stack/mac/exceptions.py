"""802.15.4 Medium Access Control Layer (MAC) exceptions
"""

class MACTimeoutException(Exception):
    """This exception is raised when a timeout occurs at MAC level.
    """
    def __init__(self):
        super().__init__()

class MACAssociationFailure(Exception):
    """This exception is raised when association fails at MAC level.
    """
    def __init__(self, reason):
        super().__init__()
        self.reason = reason
