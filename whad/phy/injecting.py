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
class LoRaConfiguration:
    """
    Configuration for LoRa modulation.

    :param spreading_factor: select the spreading factor (sf)
    :param coding_rate: select the coding rate (cr)
    :param bandwidth: select the bandwidth (bw)
    :param enable_crc: enable LoRa CRC (crc)
    :param enable_explicit_mode: enable LoRa explicit mode (em)
    """
    spreading_factor : int = 7
    coding_rate : int = 45
    bandwidth : int = 125000
    enable_crc: bool = False
    enable_explicit_mode: bool = False


@dataclass
class InjectionConfiguration:
    """
    Configuration for injecting Phy communications.

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
    :param lora: select LoRa modulation (lora)
    """
    frequency : int = None
    little_endian : bool = False
    datarate : int = None
    packet_size : int = None
    sync_word : bytes = None
    ask: bool = False
    gfsk: bool = False
    bfsk: bool = False
    qfsk: bool = False
    bpsk: bool = False
    qpsk: bool = False
    lora: bool = False
    fsk_configuration: FSKConfiguration = None
    lora_configuration: LoRaConfiguration = None
