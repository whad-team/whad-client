"""WHAD Protocol BLE pdu messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import CentralModeCmd
from whad.hub.message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper, \
    PbFieldBool, PbPacketMessageWrapper
from whad.hub.ble import BleDomain, AdvType
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA, BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP, \
    BTLE_RF, BTLE_CTRL
from struct import pack

# correlation table
SCAPY_CORR_ADV = {
    AdvType.ADV_IND: BTLE_ADV_IND,
    AdvType.ADV_NONCONN_IND: BTLE_ADV_NONCONN_IND,
    AdvType.ADV_DIRECT_IND: BTLE_ADV_DIRECT_IND,
    AdvType.ADV_SCAN_IND: BTLE_ADV_SCAN_IND,
    AdvType.ADV_SCAN_RSP: BTLE_SCAN_RSP
}

@pb_bind(BleDomain, "set_adv_data", 1)
class SetAdvData(PbMessageWrapper):
    """BLE set advertising data message class
    """
    scan_data = PbFieldBytes("ble.set_adv_data.scan_data")
    scanrsp_data = PbFieldBytes("ble.set_adv_data.scanrsp_data")

@pb_bind(BleDomain, "send_raw_pdu", 1)
class SendBleRawPdu(PbPacketMessageWrapper):
    """BLE send raw PDU message class
    """
    direction = PbFieldInt("ble.send_raw_pdu.direction")
    conn_handle = PbFieldInt("ble.send_raw_pdu.conn_handle")
    access_address = PbFieldInt("ble.send_raw_pdu.access_address")
    pdu = PbFieldBytes("ble.send_raw_pdu.pdu")
    crc = PbFieldInt("ble.send_raw_pdu.crc")
    encrypt = PbFieldBool("ble.send_raw_pdu.encrypt")


    def to_scapy(self):
        # Import here to prevent circular import
        from whad.ble.metadata import generate_ble_metadata
        packet = BTLE(
            bytes(
                pack("I", self.access_address)
            ) +
            bytes(self.pdu) +
            bytes(pack(">I", self.crc)[1:])
        )
        packet.metadata = generate_ble_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        return cls(
            direction = packet.metadata.direction,
            access_address = packet.access_addr,
            crc = packet.crc,
            pdu = bytes(packet)[4:-3],
            conn_handle = packet.metadata.connection_handle
        )

@pb_bind(BleDomain, "send_pdu", 1)
class SendBlePdu(PbPacketMessageWrapper):
    """BLE send PDU message class
    """
    direction = PbFieldInt("ble.send_pdu.direction")
    conn_handle = PbFieldInt("ble.send_pdu.conn_handle")
    pdu = PbFieldBytes("ble.send_pdu.pdu")
    encrypt = PbFieldBool("ble.send_pdu.encrypt")



    def to_scapy(self):
        # Import here to prevent circular import
        from whad.ble.metadata import generate_ble_metadata
        packet = BTLE_DATA(bytes(self.pdu))
        packet.metadata = generate_ble_metadata(self)
        return packet


    @classmethod
    def from_scapy(cls, packet):
        return cls(
            direction = packet.metadata.direction,
            pdu = bytes(packet),
            conn_handle = packet.metadata.connection_handle
        )

@pb_bind(BleDomain, "adv_pdu", 1)
class BleAdvPduReceived(PbPacketMessageWrapper):
    """BLE advertising PDU received message class
    """
    adv_type = PbFieldInt("ble.adv_pdu.adv_type")
    rssi = PbFieldInt("ble.adv_pdu.rssi")
    bd_address = PbFieldBytes("ble.adv_pdu.bd_address")
    adv_data = PbFieldBytes("ble.adv_pdu.adv_data")
    addr_type = PbFieldInt("ble.adv_pdu.addr_type")


    def to_scapy(self):
        # Import here to prevent circular import
        from whad.ble.metadata import generate_ble_metadata
        if self.adv_type in SCAPY_CORR_ADV:
            data = bytes(self.adv_data)

            packet = BTLE_ADV()/SCAPY_CORR_ADV[self.adv_type](
                bytes(self.bd_address) + data
            )
            packet.metadata = generate_ble_metadata(message)
            return packet


    @classmethod
    def from_scapy(cls, packet):
        return cls(
            adv_type = packet.PDU_type,
            rssi = packet.metadata.rssi,
            bd_address = packet.metadata.bd_address,
            adv_data = bytes(packet[BTLE_ADV:][1:]),
            addr_type = packet.metadata.addr_type
        )

@pb_bind(BleDomain, "pdu", 1)
class BlePduReceived(PbPacketMessageWrapper):
    """BLE PDU received message class
    """
    direction = PbFieldInt("ble.pdu.direction")
    pdu = PbFieldBytes("ble.pdu.pdu")
    conn_handle = PbFieldInt("ble.pdu.conn_handle")
    processed = PbFieldBool("ble.pdu.processed")
    decrypted = PbFieldBool("ble.pdu.decrypted")


    def to_scapy(self):
        # Import here to prevent circular import
        from whad.ble.metadata import generate_ble_metadata
        packet = BTLE_DATA(bytes(self.pdu))
        packet.metadata = generate_ble_metadata(self)
        return packet


    @classmethod
    def from_scapy(cls, packet):
        return cls(
            direction = packet.metadata.direction,
            pdu = bytes(packet),
            conn_handle = packet.metadata.connection_handle,
            processed = False,
            decrypted = packet.metadata.decrypted
        )

@pb_bind(BleDomain, "raw_pdu", 1)
class BleRawPduReceived(PbPacketMessageWrapper):
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

    def to_scapy(self):
        # Import here to prevent circular import
        from whad.ble.metadata import generate_ble_metadata
        packet = BTLE(
            bytes(
                pack("I", self.access_address)
            ) +
            bytes(self.pdu) +
            bytes(pack(">I", self.crc)[1:])
        )
        packet.metadata = generate_ble_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        return cls(
            direction = packet.metadata.direction,
            channel = packet.metadata.channel,
            rssi = packet.metadata.rssi,
            timestamp = packet.metadata.timestamp,
            relative_timestamp = packet.metadata.relative_timestamp,
            crc_validity = packet.metadata.is_crc_valid,
            pdu = bytes(packet)[4:-3],
            access_address = packet.access_addr,
            crc = packet.crc,
            conn_handle = packet.metadata.connection_handle,
            processed = False,
            decrypted = packet.metadata.decrypted
        )

@pb_bind(BleDomain, "injected", 1)
class Injected(PbMessageWrapper):
    """BLE PDU injected notification message class
    """
    success = PbFieldBool("ble.injected.success")
    access_address = PbFieldInt("ble.injected.access_address")
    injection_attempts = PbFieldInt("ble.injected.injection_attempts")
