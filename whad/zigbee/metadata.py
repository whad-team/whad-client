from whad.common.metadata import Metadata
from whad.zigbee.utils.phy import channel_to_frequency
from whad.scapy.layers.dot15d4tap import Dot15d4TAP_Hdr, Dot15d4TAP_TLV_Hdr,\
    Dot15d4TAP_Received_Signal_Strength, Dot15d4TAP_Channel_Assignment, \
    Dot15d4TAP_Channel_Center_Frequency, Dot15d4TAP_Link_Quality_Indicator
from dataclasses import dataclass

@dataclass
class ZigbeeMetadata(Metadata):
    is_fcs_valid : bool = None
    lqi : int = None

    def convert_to_header(self):
        timestamp = None
        tlv = []
        if self.timestamp is not None:
            timestamp = self.timestamp
        if self.rssi is not None:
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Received_Signal_Strength(rss = self.rssi))
        if self.lqi is not None:
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Link_Quality_Indicator(lqi = self.lqi))
        if self.channel is not None:
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Channel_Assignment(channel_number=self.channel, channel_page=0))
            channel_frequency = channel_to_frequency(self.channel) * 1000
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Channel_Center_Frequency(channel_frequency=channel_frequency))
        return Dot15d4TAP_Hdr(data=tlv), timestamp

def generate_zigbee_metadata(message, msg_type):
    metadata = ZigbeeMetadata()

    if msg_type == "raw_pdu":
        message = message.raw_pdu
    elif msg_type == "pdu":
        message = message.pdu

    if message.HasField("lqi"):
        metadata.lqi = message.lqi
    if message.HasField("rssi"):
        metadata.rssi = message.rssi
    metadata.channel = message.channel
    if message.HasField("timestamp"):
        metadata.timestamp = message.timestamp
    if message.HasField("fcs_validity"):
        metadata.is_fcs_valid = message.fcs_validity

    return metadata
