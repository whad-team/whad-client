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
        
class MissingEncryptionKey(Exception):
    def __init__(self, dst):
        message = f"No key is stored for communications between manager and {dst}"
        super().__init__(message)

class MissingLink(Exception):
    def __init__(self, src, dst, type):
        message = f"No Link is stored for communications between {src} and {dst} of type {type}"
        super().__init__(message)