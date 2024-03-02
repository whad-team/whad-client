"""
Exceptions related to RF4CE domain.
"""
class MissingRF4CEHeader(Exception):
    def __init__(self):
        super().__init__()

class MissingRF4CESecurityFlag(Exception):
    def __init__(self):
        super().__init__()

class MissingCryptographicMaterial(Exception):
    def __init__(self):
        super().__init__()
