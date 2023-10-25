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

    def __repr__(self):
        return "NoModulation: No modulation provided"

class NoDatarate(Exception):
    def __init__(self):
        super().__init__()

    def __repr__(self):
        return "NoDatarate: No datarate provided"

class NoFrequency(Exception):
    def __init__(self):
        super().__init__()

    def __repr__(self):
        return "NoFrequency: No frequency provided"

class NoSyncWord(Exception):
    def __init__(self):
        super().__init__()

    def __repr__(self):
        return "NoSyncWord: No synchronization word provided"

class NoEndianess(Exception):
    def __init__(self):
        super().__init__()

    def __repr__(self):
        return "NoEndianness: No endianness provided"

class NoPacketSize(Exception):
    def __init__(self):
        super().__init__()

    def __repr__(self):
        return "NoPacketSize: No packet size provided"
    
class InvalidParameter(Exception):
    def __init__(self, parameter):
        super().__init__()
        self.__parameter = parameter

    def __repr__(self):
        return "InvalidParameter: provided %s parameter is not valid" % (self.__parameter)
    
class ScheduleFifoFull(Exception):
    def __init__(self):
        super().__init__()

    def __repr__(self):
        return "Schedule packets FIFO is full"
