"""WHAD Protocol BLE pdu messages abstraction layer.
"""
import struct
from scapy.compat import raw
from scapy.layers.bluetooth4LE import BTLE, BTLE_DATA, BTLE_CTRL, BTLE_ADV
from whad.hub.metadata import BLEMetadata
from whad.hub.message import AbstractPacket

from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import CentralModeCmd
from whad.hub.message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper, \
    PbFieldBool
from whad.hub.ble import BleDomain

@pb_bind(BleDomain, "set_adv_data", 1)
class SetAdvData(PbMessageWrapper):
    """BLE set advertising data message class
    """
    scan_data = PbFieldBytes("ble.set_adv_data.scan_data")
    scanrsp_data = PbFieldBytes("ble.set_adv_data.scanrsp_data")

@pb_bind(BleDomain, "send_raw_pdu", 1)
class SendBleRawPdu(PbMessageWrapper):
    """BLE send raw PDU message class
    """
    direction = PbFieldInt("ble.send_raw_pdu.direction")
    conn_handle = PbFieldInt("ble.send_raw_pdu.conn_handle")
    access_address = PbFieldInt("ble.send_raw_pdu.access_address")
    pdu = PbFieldBytes("ble.send_raw_pdu.pdu")
    crc = PbFieldInt("ble.send_raw_pdu.crc")
    encrypt = PbFieldBool("ble.send_raw_pdu.encrypt")

@pb_bind(BleDomain, "send_pdu", 1)
class SendBlePdu(PbMessageWrapper):
    """BLE send PDU message class
    """
    direction = PbFieldInt("ble.send_pdu.direction")
    conn_handle = PbFieldInt("ble.send_pdu.conn_handle")
    pdu = PbFieldBytes("ble.send_pdu.pdu")
    encrypt = PbFieldBool("ble.send_pdu.encrypt")

@pb_bind(BleDomain, "adv_pdu", 1)
class BleAdvPduReceived(PbMessageWrapper):
    """BLE advertising PDU received message class
    """
    adv_type = PbFieldInt("ble.adv_pdu.adv_type")
    rssi = PbFieldInt("ble.adv_pdu.rssi")
    bd_address = PbFieldBytes("ble.adv_pdu.bd_address")
    adv_data = PbFieldBytes("ble.adv_pdu.adv_data")
    addr_type = PbFieldInt("ble.adv_pdu.addr_type")


@pb_bind(BleDomain, "pdu", 1)
class BlePduReceived(PbMessageWrapper):
    """BLE PDU received message class
    """
    direction = PbFieldInt("ble.pdu.direction")
    pdu = PbFieldBytes("ble.pdu.pdu")
    conn_handle = PbFieldInt("ble.pdu.conn_handle")
    processed = PbFieldBool("ble.pdu.processed")
    decrypted = PbFieldBool("ble.pdu.decrypted")

    def to_packet(self):
        """Convert message into its corresponding Scapy packet
        """
        packet = BTLE_DATA(self.pdu)
        packet.metadata = BLEMetadata()
        packet.metadata.connection_handle = self.conn_handle
        packet.metadata.direction = self.direction
        packet.metadata.decrypted = self.decrypted
        return packet

    @staticmethod
    def from_packet(packet):
        """Convert packet into BlePduReceived message
        """
        return BlePduReceived(
            pdu=bytes(packet),
            direction=packet.metadata.direction,
            conn_handle=packet.metadata.connection_handle,
            processed=False,
            decrypted=packet.metadata.decrypted
        )


@pb_bind(BleDomain, "raw_pdu", 1)
class BleRawPduReceived(PbMessageWrapper):
    """BLE raw PDU received message class
    """
    direction = PbFieldInt("ble.raw_pdu.direction")
    channel = PbFieldInt("ble.raw_pdu.channel")
    rssi = PbFieldInt("ble.raw_pdu.rssi")
    timestamp = PbFieldInt("ble.raw_pdu.timestamp")
    relative_timestamp = PbFieldInt("ble.raw_pdu.relative_timestamp")
    crc_validity = PbFieldBool("ble.raw_pdu.crc_validity")
    access_address = PbFieldInt("ble.raw_pdu.access_address")
    pdu = PbFieldBytes("ble.raw_pdu.pdu")
    crc = PbFieldInt("ble.raw_pdu.crc")
    conn_handle = PbFieldInt("ble.raw_pdu.conn_handle")
    processed = PbFieldBool("ble.raw_pdu.processed")
    decrypted = PbFieldBool("ble.raw_pdu.decrypted")

    def to_packet(self):
        """Convert message into its corresponding Scapy packet
        """
        packet = BTLE(bytes(struct.pack("I", self.access_address)) + bytes(self.pdu) + bytes(struct.pack(">I", self.crc)[1:]))
        
        # Populate metadata
        packet.metadata = BLEMetadata()
        packet.metadata.direction = self.direction
        packet.metadata.connection_handle = self.conn_handle
        packet.metadata.channel = self.channel
        if self.rssi is not None:
            packet.metadata.rssi = self.rssi
        if self.timestamp is not None:
            packet.metadata.timestamp = self.timestamp
        if self.crc_validity is not None:
            packet.metadata.is_crc_valid = self.crc_validity
        if self.relative_timestamp is not None:
            packet.metadata.relative_timestamp = self.relative_timestamp
        packet.metadata.decrypted = self.decrypted
        return packet
    
    @staticmethod
    def from_packet(packet):
        """Create message from Scapy packet
        """

        if BTLE in packet:
            # Extract PDU
            if BTLE_DATA in packet:
                pdu = raw(packet[BTLE_DATA:])
            elif BTLE_CTRL in packet:
                pdu = raw(packet[BTLE_CTRL:])
            elif BTLE_ADV in packet:
                pdu = raw(packet[BTLE_ADV:])
            else:
                return None
            
            return BleRawPduReceived(
                pdu=pdu,
                access_address=BTLE(raw(packet)).access_addr,
                crc=BTLE(raw(packet)).crc,
                direction=packet.metadata.direction,
                conn_handle=packet.metadata.connection_handle,
                channel=packet.metadata.channel,
                rssi=packet.metadata.rssi,
                timestamp=packet.metadata.timestamp,
                crc_validity=packet.metadata.is_crc_valid,
                relative_timestamp=packet.metadata.relative_timestamp,
                decrypted=packet.metadata.decrypted
            )
        
        return None




@pb_bind(BleDomain, "injected", 1)
class Injected(PbMessageWrapper):
    """BLE PDU injected notification message class
    """
    success = PbFieldBool("ble.injected.success")
    access_address = PbFieldInt("ble.injected.access_address")
    injection_attempts = PbFieldInt("ble.injected.injection_attempts")
