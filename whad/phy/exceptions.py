"""Physical layer domain exceptions
"""

class UnknownPhysicalLayer(Exception):
    def __init__(self):
        super().__init__()

class UnknownPhysicalLayerFunction(Exception):
    def __init__(self, missing_function):
        self.missing_function = missing_function
        super().__init__()

class UnsupportedFrequency(Exception):
    def __init__(self, frequency):
        super().__init__(self, frequency)

class NoModulation(Exception):
    def __init__(self):
        super().__init__()
