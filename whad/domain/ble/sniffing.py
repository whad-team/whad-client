from dataclasses import dataclass

@dataclass
class SynchronizedConnection:
    access_address : int = None
    crc_init : int = None
    hop_interval : int = None
    hop_increment : int = None
    channel_map : int = None

@dataclass
class SnifferConfiguration:
    show_advertisements : bool = True
    follow_connection : bool = False
    show_empty_packets : bool = False
    channel : int = 37
    filter : str = "FF:FF:FF:FF:FF:FF"
