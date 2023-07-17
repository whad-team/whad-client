class ModulationScheme:
    def __init__(self, symbols):
        self.symbols = symbols

    def __repr__(self):
        return self.__class__.__name__+"(symbols=({}))".format(",".join(self.symbols))

class ASKModulationScheme(ModulationScheme):
    def __init__(self, symbols, on_off_keying=False):
        self.on_off_keying = on_off_keying
        super().__init__(symbols)

class OOKModulationScheme(ASKModulationScheme):
    def __init__(self):
        super().__init__(("0", "1"), on_off_keying=True)

class FSKModulationScheme(ModulationScheme):
    def __init__(self, symbols, deviation, gaussian_filter=False):
        self.deviation = deviation
        self.gaussian_filter = gaussian_filter
        super().__init__(symbols)

class QFSKModulationScheme(FSKModulationScheme):
    def __init__(self, deviation):
        super().__init__(("00", "01", "11", "10"), deviation=deviation)


class GFSKModulationScheme(FSKModulationScheme):
    def __init__(self, deviation):
        super().__init__(("0", "1"), deviation, gaussian_filter=True)

class PSKModulationScheme(ModulationScheme):
    def __init__(self, symbols, offset_mode=False):
        self.offset_mode = offset_mode
        super().__init__(symbols)

class BPSKModulationScheme(PSKModulationScheme):
    def __init__(self, offset_mode=False):
        super().__init__(("0", "1"), offset_mode)


class QPSKModulationScheme(PSKModulationScheme):
    def __init__(self, offset_mode=False):
        super().__init__(("00", "01", "10", "11"), offset_mode)

class OQPSKModulationScheme(QPSKModulationScheme):
    def __init__(self):
        super().__init__(offset_mode=True)

class PhysicalLayer:
    def __init__(self, modulation, datarate, endianness, synchronization_word, frequency_range, maximum_packet_size, configuration=None, scapy_layer=None, channel_to_frequency_function=None, frequency_to_channel_function=None, format_address_function=None, integrity_function=None, decoding_function=None, encoding_function=None):
        self.modulation = modulation
        self.datarate = datarate
        self.endianness = endianness
        self.synchronization_word = synchronization_word
        self.frequency_range = frequency_range
        self.maximum_packet_size = maximum_packet_size
        self.configuration = configuration
        self.scapy_layer = scapy_layer
        self.channel_to_frequency = channel_to_frequency_function
        self.frequency_to_channel = frequency_to_channel_function
        self.format_address = format_address_function
        self.integrity = integrity_function
        self.decoding = decoding_function
        self.encoding = encoding_function
