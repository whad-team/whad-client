'''
This module provides some helpers functions and constants related to 802.15.4 physical layer.
'''
from whad.phy import OQPSKModulationScheme, PhysicalLayer, Endianness
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

PHYS = {
    "802.15.4-OQPSK": PhysicalLayer(
                        modulation=OQPSKModulationScheme(),
                        datarate=250000,
                        endianness=Endianness.LITTLE,
                        frequency_range=(2405, 2480),
                        maximum_packet_size=255, 
                        synchronization_word=b"\x00\x00\x00\x00\xA7",
                        frequency_to_channel_function=frequency_to_channel,
                        channel_to_frequency_function=channel_to_frequency
                    )
}
