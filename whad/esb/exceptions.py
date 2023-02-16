"""Enhanced ShockBurst domain exceptions
"""

class InvalidESBAddressException(Exception):
    """Invalid ESB address used
    """
    def __init__(self):
        super().__init__()
