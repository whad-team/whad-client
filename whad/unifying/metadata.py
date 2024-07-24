from whad.common.metadata import Metadata
from dataclasses import dataclass
from whad.scapy.layers.esb import ESB_Hdr
from whad.esb.esbaddr import ESBAddress

@dataclass(repr=False)
class UnifyingMetadata(Metadata):
    is_crc_valid : bool = None
    address : str = None

    def convert_to_header(self):
        return None, timestamp

    @classmethod
    def convert_from_header(cls, pkt):
        metadata = UnifyingMetadata()
        pkt = ESB_Hdr(bytes(pkt))
        metadata.address = ESBAddress(pkt.address)
        metadata.is_crc_valid = pkt.valid_crc
        metadata.timestamp = int(100000 * pkt.time)
        metadata.channel = 0
        return metadata

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
