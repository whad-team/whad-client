from whad.common.metadata import Metadata
from dataclasses import dataclass, field

@dataclass(repr=False)
class PhyMetadata(Metadata):
    frequency : int = None
    iq : list = field(default_factory=lambda: [])

    def convert_to_header(self):
        return None, timestamp

def generate_phy_metadata(message, msg_type):
    metadata = PhyMetadata()

    if msg_type == "raw_packet":
        message = message.raw_packet
    elif msg_type == "packet":
        message = message.packet

    if message.HasField("rssi"):
        metadata.rssi = message.rssi

    metadata.frequency = message.frequency

    if message.HasField("timestamp"):
        metadata.timestamp = message.timestamp
    try:
        if message.HasField("iq"):
            metadata.iq = [complex(message.iq[i], message.iq[i+1]) for i in range(0,len(message.iq)-1,2)]
    except ValueError:
        pass
    return metadata
