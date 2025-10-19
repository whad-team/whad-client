from dataclasses import dataclass
from enum import IntEnum

@dataclass
class Network:
    network_key : bytes = None
    sync_word : int = None