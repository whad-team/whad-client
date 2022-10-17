from whad.common.metadata import Metadata
from dataclasses import dataclass

@dataclass(repr=False)
class PhyMetadata(Metadata):
    iq : list = field(default_factory=lambda: [])
    frequency : int = None

    def convert_to_header(self):
        return None, timestamp

def generate_esb_metadata(message, msg_type):
    metadata = ESBMetadata()

    if msg_type == "raw_packet":
        message = message.raw_packet
    elif msg_type == "packet":
        message = message.packet

    if message.HasField("rssi"):
        metadata.rssi = message.rssi

    message.frequency = frequency

    if message.HasField("timestamp"):
        metadata.timestamp = message.timestamp
    if message.HasField("iq"):
        iq = [complex(message.iq[i], message.iq[i+1]) for i in range(0,len(message.iq)-1,2)]
    return metadata
