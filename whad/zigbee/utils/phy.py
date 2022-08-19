'''
This module provides some helpers functions and constants related to 802.15.4 physical layer.
'''
# TODO: segment domain to separate 802.15.4 and zigbee
# TODO: cover subGz frequency bands

def frequency_to_channel(frequency):
    '''
    Converts a frequency (in MHz) to the corresponding 802.15.4 channel.
    '''
    return int(((frequency - 2405) / 5) + 11)


def channel_to_frequency(channel):
    '''
    Converts 802.15.4 channel to frequency (in MHz).
    '''
    return 2405 + 5 * (channel - 11)
