from typing import Union
from scapy.layers.bluetooth4LE import BTLE_RF
from whad.common.metadata import Metadata
from whad.scapy.layers.dot15d4tap import Dot15d4TAP_Hdr, Dot15d4TAP_TLV_Hdr,\
    Dot15d4TAP_Received_Signal_Strength, Dot15d4TAP_Channel_Assignment, \
    Dot15d4TAP_Channel_Center_Frequency, Dot15d4TAP_Link_Quality_Indicator
from dataclasses import dataclass, field, fields


def channel_to_frequency(channel):
    '''
    Converts 802.15.4 channel to frequency (in Hz).
    '''
    return 1000000 * (2405 + 5 * (channel - 11))

@dataclass(repr=False)
class Metadata:
    raw : bool = None
    timestamp : Union[int, float] = None
    channel : int = None
    rssi : int = None

    def convert_to_header(self):
        pass

    def __repr__(self):
        metadatas = []
        for field in fields(self.__class__):
            if hasattr(self, field.name) and getattr(self,field.name) is not None:
                metadatas.append("{}={}".format(field.name, getattr(self,field.name)))

        if len(metadatas) == 0:
            return ""
        else:
            return "[ " + ", ".join(metadatas) + " ]"


@dataclass(repr=False)
class Dot15d4Metadata(Metadata):
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

@dataclass(repr=False)
class ESBMetadata(Metadata):
    is_crc_valid : bool = None
    address : str = None

    def convert_to_header(self):
        return None, self.timestamp

@dataclass(repr=False)
class PhyMetadata(Metadata):
    frequency : int = None
    iq : list = field(default_factory=lambda: [])

    def convert_to_header(self):
        return None, self.timestamp