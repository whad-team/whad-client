from dataclasses import dataclass, field
from whad.phy import Endianness

@dataclass
class FSKConfiguration:
    """
    Configuration for FSK modulation.

    :param deviation: select the modulation deviation (dev)
    """
    deviation : int = 500000

@dataclass
class SnifferConfiguration:
    """
    Configuration for sniffing Phy communications.

    :param frequency: select the frequency to sniff (f)
    :param little_endian: select little endianness (le)
    :param datarate: select number of bits per second (d)
    :param packet_size: select packet size (s)
    :param sync_word: select synchronization word (w)
    :param ask: select ASK modulation (ask)
    :param gfsk: select GFSK modulation (gfsk)
    :param bfsk: select BFSK modulation (bfsk)
    :param qfsk: select QFSK modulation (qfsk)
    :param bpsk: select BPSK modulation (bpsk)
    :param qpsk: select QPSK modulation (qpsk)

    """
    frequency : int = 2402000000
    little_endian : bool = False
    datarate : int = 100000
    packet_size : int = 31
    sync_word : bytes = b"\xAA"
    ask: bool = False
    gfsk: bool = False
    bfsk: bool = False
    qfsk: bool = False
    bpsk: bool = False
    qpsk: bool = False
    fsk_configuration: FSKConfiguration = None
