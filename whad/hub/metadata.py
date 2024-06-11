from scapy.layers.bluetooth4LE import BTLE_RF
from whad.common.metadata import Metadata
from whad.scapy.layers.dot15d4tap import Dot15d4TAP_Hdr, Dot15d4TAP_TLV_Hdr,\
    Dot15d4TAP_Received_Signal_Strength, Dot15d4TAP_Channel_Assignment, \
    Dot15d4TAP_Channel_Center_Frequency, Dot15d4TAP_Link_Quality_Indicator
from whad.hub.ble import Direction as BleDirection
from dataclasses import dataclass, field


def channel_to_frequency(channel):
    '''
    Converts 802.15.4 channel to frequency (in Hz).
    '''
    return 1000000 * (2405 + 5 * (channel - 11))

@dataclass(repr=False)
class BLEMetadata(Metadata):
    direction : BleDirection = None
    connection_handle : int = None
    is_crc_valid : bool = None
    relative_timestamp : int = None
    decrypted : bool = None
    processed : bool = None

    def convert_to_header(self):
        timestamp = None
        packet_type = 0 # ADV_OR_DATA_UNKNOWN_DIR
        signal = -128
        crc_checked = 0
        crc_valid = 0
        sig_power_valid = 0
        dewhitened = 1
        rf_channel = 0
        if self.direction is not None:
            if self.direction == BleDirection.MASTER_TO_SLAVE:
                packet_type = 2
            elif self.direction == BleDirection.SLAVE_TO_MASTER:
                packet_type = 3
        if self.timestamp is not None:
            timestamp = self.timestamp
        if self.rssi is not None:
            sig_power_valid = 1
            signal = self.rssi
        if self.is_crc_valid is not None:
            crc_checked = 1
            crc_valid = self.is_crc_valid
        if self.channel is not None:
            rf_channel = self.channel

        header = BTLE_RF(
            rf_channel = rf_channel,
            type = packet_type,
            signal = signal,
            crc_checked = crc_checked,
            crc_valid = crc_valid,
            sig_power_valid = sig_power_valid,
            dewhitened = dewhitened
        )
        return header, timestamp


@dataclass(repr=False)
class Dot15d4Metadata(Metadata):
    is_fcs_valid : bool = None
    lqi : int = None
    timestamp : int = None

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
    timestamp : int = None

    def convert_to_header(self):
        return None, self.timestamp

@dataclass(repr=False)
class PhyMetadata(Metadata):
    frequency : int = None
    iq : list = field(default_factory=lambda: [])
    timestamp : float = None

    def convert_to_header(self):
        return None, self.timestamp