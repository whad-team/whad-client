'''
This module provides some helpers functions related to Bluetooth Low Energy physical layer.
'''
from whad.helpers import swap_bits

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
