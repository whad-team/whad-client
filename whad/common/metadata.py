from dataclasses import dataclass

@dataclass
class Metadata:
    timestamp : int = None
    channel : int = None
    rssi : int = None

    def convert_to_header(self):
        pass
