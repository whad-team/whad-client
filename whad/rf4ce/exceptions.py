"""
Exceptions related to RF4CE domain.
"""
class MissingRF4CEHeader(Exception):
    """RF4CE header is missing."""

    def __init__(self):
        """Constructor."""
        super().__init__()

class MissingRF4CESecurityFlag(Exception):
    """RF4CE Security Flag is missing.
    """
    def __init__(self):
        """Constructor."""
        super().__init__()

class MissingCryptographicMaterial(Exception):
    """Crypto material is missing."""

    def __init__(self):
        """Constructor."""
        super().__init__()
