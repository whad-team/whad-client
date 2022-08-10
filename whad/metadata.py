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
class ZigbeeMetadata(Metadata):
    is_fcs_valid : bool = None

@dataclass
class BLEMetadata(Metadata):
    direction : BleDirection = None
    connection_handle : int = None
    is_crc_valid : bool = None
    relative_timestamp : int = None

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

        metadata.connection_handle = message.conn_handle

    elif msg_type == "adv_pdu":
        message = message.adv_pdu
        metadata.direction = BleDirection.UNKNOWN
        metadata.rssi = message.rssi

    elif msg_type == "pdu":
        message = message.pdu
        metadata.connection_handle = message.conn_handle
        metadata.direction = message.direction

    return metadata

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
