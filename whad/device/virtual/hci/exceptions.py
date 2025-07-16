"""
Exceptions for WHAD's HCI virtual device
"""

class HCIUnsupportedCommand(Exception):
    """Raised when an HCI command requirement is not met by hardware.
    """
    def __init__(self, command):
        super().__init__()
        self.command = command

    def __repr__(self):
        return f"HCIUnsupportedCommand(cmd='{self.command}')"

class HCIUnsupportedFeature(Exception):
    """Raised when an HCI feature requirement is not met by hardware.
    """
    def __init__(self, feature):
        super().__init__()
        self.__feature = feature

    def __repr__(self):
        return f"HCIUnsupportedFeature(feature='{self.__feature}')"

class HCIUnsupportedLEFeature(Exception):
    """Raised when an HCI LE feature requirement is not met by hardware.
    """
    def __init__(self, feature):
        super().__init__()
        self.__feature = feature

    def __repr__(self):
        return f"HCIUnsupportedLEFeature(feature='{self.__feature}')"

