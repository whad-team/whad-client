from whad.common.metadata import Metadata
from dataclasses import dataclass

@dataclass
class ZigbeeMetadata(Metadata):
    is_fcs_valid : bool = None

def generate_zigbee_metadata(message, msg_type):
    metadata = ZigbeeMetadata()

    if msg_type == "raw_pdu":
        message = message.raw_pdu
    elif msg_type == "pdu":
        message = message.pdu

    if message.HasField("rssi"):
        metadata.rssi = message.rssi
    metadata.channel = message.channel
    if message.HasField("timestamp"):
        metadata.timestamp = message.timestamp
    if message.HasField("fcs_validity"):
        metadata.is_fcs_valid = message.fcs_validity

    return metadata
