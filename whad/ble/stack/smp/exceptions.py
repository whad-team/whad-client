"""Bluetooth Low Energy Secure Manager exceptions
"""

class SMInvalidParameterFormat(Exception):
    def __init__(self):
        super().__init__()

class SMInvalidCustomFunction(Exception):
    def __init__(self):
        super().__init__()

__all__ = [
    'SMInvalidParameterFormat',
    'SMInvalidCustomFunction'
]
