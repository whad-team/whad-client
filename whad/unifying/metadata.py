from whad.common.metadata import Metadata
from dataclasses import dataclass

@dataclass(repr=False)
class UnifyingMetadata(Metadata):
    is_crc_valid : bool = None
    address : str = None

    def convert_to_header(self):
        return None, timestamp

def generate_unifying_metadata(message, msg_type):
    metadata = UnifyingMetadata()

    if msg_type == "raw_pdu":
        message = message.raw_pdu
    elif msg_type == "pdu":
        message = message.pdu

    if message.HasField("rssi"):
        metadata.rssi = message.rssi
    metadata.channel = message.channel
    if message.HasField("timestamp"):
        metadata.timestamp = message.timestamp
    if message.HasField("crc_validity"):
        metadata.is_crc_valid = message.crc_validity
    if message.HasField("address"):
        metadata.address = ":".join(["{:02x}".format(i) for i in message.address])
    return metadata
