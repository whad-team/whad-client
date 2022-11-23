"""GATT exceptions
"""

class GattTimeoutException(Exception):
    def __init__(self):
        super().__init__()
