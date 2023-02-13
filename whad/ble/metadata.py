from whad.protocol.ble.ble_pb2 import BleDirection
from scapy.layers.bluetooth4LE import BTLE_RF
from whad.ble.utils.phy import channel_to_frequency
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
            rf_channel = channel_to_frequency(self.channel) - 2402

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

def generate_ble_metadata(message, msg_type):
    metadata = BLEMetadata()
    if msg_type == "raw_pdu":
        message = message.raw_pdu
        metadata.direction = message.direction
        if message.HasField("rssi"):
            metadata.rssi = message.rssi
        metadata.channel = message.channel
        if message.HasField("timestamp"):
            metadata.timestamp = message.timestamp
        if message.HasField("crc_validity"):
            metadata.is_crc_valid = message.crc_validity
        if message.HasField("relative_timestamp"):
            metadata.relative_timestamp = message.relative_timestamp
            metadata.decrypted = message.decrypted

        metadata.connection_handle = message.conn_handle

    elif msg_type == "adv_pdu":
        message = message.adv_pdu
        metadata.direction = BleDirection.UNKNOWN
        metadata.rssi = message.rssi

    elif msg_type == "pdu":
        message = message.pdu
        metadata.connection_handle = message.conn_handle
        metadata.direction = message.direction
        metadata.decrypted = message.decrypted

    elif msg_type == "send_pdu":
        message = message.send_pdu
        metadata.connection_handle = message.conn_handle
        metadata.direction = message.direction

    elif msg_type == "send_raw_pdu":
        message = message.send_raw_pdu
        metadata.direction = message.direction
        metadata.crc = message.crc
        metadata.connection_handle = message.conn_handle

    return metadata
