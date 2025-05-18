"""
WHAD Enhanced ShockBurst PHY utility functions.

This module provides some functions related to ESB PHY, allowing
channel to frequency conversion or basic PHY configurations.
"""
from enum import IntEnum

from whad.phy import PhysicalLayer, GFSKModulationScheme, Endianness
from whad.scapy.layers.esb import ESB_Hdr


class FieldsSize(IntEnum):
    '''
    Size of major ESB fields (in bytes).
    '''
    PREAMBLE_SIZE = 1
    ADDRESS_SIZE = 5
    HEADER_SIZE = 2
    CRC_SIZE = 2


def frequency_to_channel(frequency) -> int:
    """
    Converts a frequency (in Hz) to an Enhanced ShockBurst channel.
    """
    return int(frequency/1000000) - 2400

def channel_to_frequency(channel) -> int:
    """
    Converts an Enhanced ShockBurst channel into a frequency (in Hz).
    """
    return (2400 + channel) * 1000000

def decoding(pkt, configuration = None):
    """Decode a received packet depending on the current configuration.
    """
    size = (pkt[6] & 0b11111100) >> 2
    pkt_size = FieldsSize.PREAMBLE_SIZE + FieldsSize.CRC_SIZE + FieldsSize.ADDRESS_SIZE
    pkt_size += FieldsSize.HEADER_SIZE + size
    return pkt[:pkt_size]


PHYS = {
    "ESB-1M": PhysicalLayer(
                modulation=GFSKModulationScheme(deviation=170000),
                datarate=1000000,
                endianness=Endianness.BIG,
                frequency_range=(2400000000, 2500000000),
                maximum_packet_size=31,
                synchronization_word=b"\xAA",
                scapy_layer=ESB_Hdr,
                format_address_function=lambda address:bytes.fromhex(address.replace(":","")),
                frequency_to_channel_function=frequency_to_channel,
                channel_to_frequency_function=channel_to_frequency,
                encoding_function=None,
                decoding_function=decoding
            ),

    "ESB-2M": PhysicalLayer(
                modulation=GFSKModulationScheme(deviation=500000),
                datarate=2000000,
                endianness=Endianness.BIG,
                frequency_range=(2400000000, 2500000000),
                maximum_packet_size=31,
                synchronization_word=b"\xAA",
                scapy_layer=ESB_Hdr,
                format_address_function=lambda address:bytes.fromhex(address.replace(":","")),
                frequency_to_channel_function=frequency_to_channel,
                channel_to_frequency_function=channel_to_frequency,
                encoding_function=None,
                decoding_function=decoding
            )
}
