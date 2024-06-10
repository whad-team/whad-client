from whad.protocol.ble.ble_pb2 import BleDirection
from scapy.layers.bluetooth4LE import BTLE_RF
from whad.common.metadata import Metadata
from dataclasses import dataclass

@dataclass(repr=False)
class BLEMetadata(Metadata):
    direction : BleDirection = None
    connection_handle : int = None
    is_crc_valid : bool = None
    relative_timestamp : int = None
    decrypted : bool = None

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
