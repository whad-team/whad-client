'''
This module provides some helpers functions and constants related to 802.15.4 physical layer.
'''
from whad.phy import OQPSKModulationScheme, PhysicalLayer, Endianness
from struct import pack, unpack

class ChannelMap:
    def __init__(self, channels=[]):
        # This is an integer channel map directly
        if isinstance(channels, int):
            if channels >= 0 and channels <= 0xFFFF:
                self.channel_map = pack('<H', channels)
            else:
                raise ValueError()

        elif isinstance(channels, bytes):
            if len(channels) == 2:
                self.channel_map = channels
            else:
                raise ValueError()

        elif isinstance(channels, list):
            bitmap_str = "".join(['1' if i in channels else '0' for i in range(11, 27)])[::-1]
            self.channel_map = pack('<H',int(bitmap_str,2))

        else:
            raise ValueError()

    @property
    def bytes(self):
        return self.channel_map

    @property
    def value(self):
        return  unpack('<H', self.channel_map)[0]

    @property
    def list(self):
        chm = self.value
        bitmap_str = "{:016b}".format(chm)[::-1]
        return [idx+11 for idx, bit in enumerate(bitmap_str) if bit == '1']

def frequency_to_channel(frequency):
    '''
    Converts a frequency (in Hz) to the corresponding 802.15.4 channel.
    '''
    return int((((frequency / 1000000) - 2405) / 5) + 11)


def channel_to_frequency(channel):
    '''
    Converts 802.15.4 channel to frequency (in Hz).
    '''
    return 1000000 * (2405 + 5 * (channel - 11))

PHYS = {
    "802.15.4-OQPSK": PhysicalLayer(
                        modulation=OQPSKModulationScheme(),
                        datarate=250000,
                        endianness=Endianness.LITTLE,
                        frequency_range=(2405000000, 2480000000),
                        maximum_packet_size=255,
                        synchronization_word=b"\x00\x00\x00\x00\xA7",
                        frequency_to_channel_function=frequency_to_channel,
                        channel_to_frequency_function=channel_to_frequency
                    )
}
