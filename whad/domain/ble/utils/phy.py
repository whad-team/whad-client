'''
This module provides some helpers functions and constants related to Bluetooth Low Energy physical layer.
'''
from whad.helpers import swap_bits
from enum import IntEnum

# Size of major BLE fields (in bytes)
class FieldsSize(IntEnum):
    ACCESS_ADDRESS_SIZE = 4
    HEADER_SIZE = 2
    CRC_SIZE = 3


def frequency_to_channel(frequency):
    '''
    Converts a frequency (in MHz) to the corresponding BLE channel.
    '''
    if not isinstance(frequency,int) or frequency < 2402 or frequency > 2480:
        return None

    freq_offset = frequency - 2400
    if freq_offset == 2:
        channel = 37
    elif freq_offset == 26:
        channel = 38
    elif freq_offset == 80:
        channel = 39
    elif freq_offset <= 24:
        channel = int((freq_offset / 2) - 2)
    else:
        channel = int((freq_offset / 2) - 3)

    return channel

def channel_to_frequency(channel):
    '''
    Converts a BLE channel to the corresponding frequency (in MHz).
    '''
    if not isinstance(channel,int) or channel < 0 or channel > 39:
        return None
    if channel == 37:
        freq_offset = 2
    elif channel == 38:
        freq_offset = 26
    elif channel == 39:
        freq_offset = 80
    elif channel < 11:
        freq_offset = 2 * (channel + 2)
    else:
        freq_offset = 2 * (channel + 3)

    return 2400 + freq_offset

def crc(data, init=0x555555):
    '''
    Computes the 24-bit CRC of provided data.
    '''
    ret = [(init >> 16) & 0xff, (init >> 8) & 0xff, init & 0xff]
    for d in data:
        for v in range(8):
            t = (ret[0] >> 7) & 1

            ret[0] <<= 1
            if ret[1] & 0x80:
                ret[0] |= 1

            ret[1] <<= 1
            if ret[2] & 0x80:
                ret[1] |= 1

            ret[2] <<= 1
            if d & 1 != t:
                ret[2] ^= 0x5b
                ret[1] ^= 0x06

            d >>= 1

    ret[0] = swap_bits(ret[0] & 0xFF)
    ret[1] = swap_bits(ret[1] & 0xFF)
    ret[2] = swap_bits(ret[2] & 0xFF)
    return bytes(ret)
