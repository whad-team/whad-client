from whad.common.metadata import Metadata
from whad.hub.phy import PacketReceived, RawPacketReceived
from dataclasses import dataclass, field

@dataclass(repr=False)
class PhyMetadata(Metadata):
    frequency : int = None
    iq : list = field(default_factory=lambda: [])
    timestamp : float = None

    def convert_to_header(self):
        return None, self.timestamp

def generate_phy_metadata(message):
    metadata = PhyMetadata()

    if message.rssi is not None:
        metadata.rssi = message.rssi

    metadata.frequency = message.frequency

    if message.timestamp is not None:
        metadata.timestamp = message.timestamp.sec*0.001 + message.timestamp.usec*0.000001
    
    if isinstance(message, RawPacketReceived):
        if message.iq is not None:
            metadata.iq = [complex(message.iq[i], message.iq[i+1]) for i in range(0,len(message.iq)-1,2)]
    
    return metadata
