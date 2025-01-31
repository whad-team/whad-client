"""
Exceptions related to Wireless Hart domain.
"""
class MissingSecurityHeader(Exception):
    def __init__(self):
        super().__init__()

class MissingSecurityFlag(Exception):
    def __init__(self):
        super().__init__()

class MissingCryptographicMaterial(Exception):
    def __init__(self):
        super().__init__()
