from whad.common.metadata import Metadata
from whad.hub.esb import RawPduReceived, PduReceived
from dataclasses import dataclass

@dataclass(repr=False)
class ESBMetadata(Metadata):
    is_crc_valid : bool = None
    address : str = None
    timestamp : int = None

    def convert_to_header(self):
        return None, self.timestamp

def generate_esb_metadata(message):
    metadata = ESBMetadata()

    if message.rssi is not None:
        metadata.rssi = message.rssi
    metadata.channel = message.channel
    if message.timestamp is not None:
        metadata.timestamp = message.timestamp
    if message.crc_validity is not None:
        metadata.is_crc_valid = message.crc_validity
    if message.address is not None:
        metadata.address = ":".join(["{:02x}".format(i) for i in message.address])
    return metadata
