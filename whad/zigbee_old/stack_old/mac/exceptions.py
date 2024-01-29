"""MAC exceptions
"""

class MACTimeoutException(Exception):
    def __init__(self):
        super().__init__()

class MACAssociationFailure(Exception):
    def __init__(self, reason):
        super().__init__()
        self.reason = reason
