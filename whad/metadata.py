from whad.protocol.ble.ble_pb2 import BleDirection
from whad.helpers import is_message_type
from dataclasses import dataclass
from enum import IntEnum

@dataclass
class Metadata:
    timestamp : int = None
    channel : int = None
    rssi : int = None

@dataclass
class BLEMetadata(Metadata):
    direction : BleDirection = None
    connection_handle : int = None
    is_crc_valid : bool = None
    relative_timestamp : int = None

def generate_metadata(message):
    metadata = BLEMetadata()
    if is_message_type(message, "ble", "raw_pdu"):
        message = message.ble.raw_pdu
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

    elif is_message_type(message, "ble", "adv_pdu"):
        message = message.ble.adv_pdu
        metadata.direction = BleDirection.UNKNOWN
        metadata.rssi = message.rssi
        
    elif is_message_type(message, "ble", "pdu"):
        message = message.ble.pdu
        metadata.connection_handle = message.ble.pdu.connection_handle
        metadata.direction = message.direction

    metadata = BLEMetadata()
    return metadata
