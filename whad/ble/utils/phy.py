'''
This module provides some helpers functions and constants related to Bluetooth Low Energy physical layer.
'''
from whad.helpers import swap_bits
from whad.phy import Endianness, GFSKModulationScheme, PhysicalLayer
from enum import IntEnum

class FieldsSize(IntEnum):
    '''
    Size of major BLE fields (in bytes).
    '''
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

def dewhitening(data, channel):
  '''
  Dewhiten data based on BLE channel.
  '''
  ret = []
  lfsr = swap_bits(channel) | 2

  for d in data:
    d = swap_bits(d)
    for i in 128, 64, 32, 16, 8, 4, 2, 1:
      if lfsr & 0x80:
        lfsr ^= 0x11
        d ^= i

      lfsr <<= 1
      i >>=1
    ret.append(swap_bits(d))

  return bytes(ret)

def whitening(data, channel):
    '''
    Whiten data based on a BLE channel.
    '''
    return dewhitening(data, channel)

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



def is_access_address_valid(aa):
    '''
    This function checks if the provided access address is valid.
    '''
    a = (aa & 0xff000000)>>24
    b = (aa & 0x00ff0000)>>16
    c = (aa & 0x0000ff00)>>8
    d = (aa & 0x000000ff)
    if a==b and b==c and c==d:
        return False
    if (aa == 0x8E89BED6):
        return True
    bb = aa
    for i in range(0,26):
        if (bb & 0x3F) == 0 or (bb & 0x3F) == 0x3F:
            return False
        bb >>= 1
    bb = aa
    t = 0
    a = (bb & 0x80000000)>>31
    for i in range(30,0,-1):
        if (bb & (1<<i)) >> i != a:
            a = (bb & (1<<i))>>i
            t += 1
            if t>24:
                return False
        if (i<26) and (t<2):
            return False
    return True

PHYS = {
    "LE-1M": PhysicalLayer(
                modulation=GFSKModulationScheme(deviation=250000),
                datarate=1000000,
                endianness=Endianness.LITTLE,
                frequency_range=(2402, 2480),
                maximum_packet_size=255,
                synchronization_word=b"\xAA",
                frequency_to_channel_function=frequency_to_channel,
                channel_to_frequency_function=channel_to_frequency,
                integrity_function=crc,
                encoding_function=whitening,
                decoding_function=dewhitening
            ),

    "LE-2M": PhysicalLayer(
                modulation=GFSKModulationScheme(deviation=500000),
                datarate=2000000,
                endianness=Endianness.LITTLE,
                frequency_range=(2402, 2480), 
                maximum_packet_size=255,
                synchronization_word=b"\xAA\xAA",
                frequency_to_channel_function=frequency_to_channel,
                channel_to_frequency_function=channel_to_frequency,
                integrity_function=crc,
                encoding_function=whitening,
                decoding_function=dewhitening
            )
}
