from dataclasses import dataclass

@dataclass
class Metadata:
    timestamp : int = None
    channel : int = None
    rssi : int = None
