"""WHAD Protocol BLE pdu messages abstraction layer.
"""
import struct
from scapy.compat import raw
from scapy.layers.bluetooth4LE import BTLE, BTLE_DATA, BTLE_CTRL, BTLE_ADV, BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP
from whad.hub.message import AbstractPacket
from whad.hub.ble import Direction, AdvType, AddressType, BDAddress, BLEMetadata

from whad.hub.message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper, \
    PbFieldBool
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


def packet_to_bytes(packet):
    """Convert packet to bytes
    """
    try:
        return raw(packet)
    except TypeError as type_err:
        return bytes(packet.__bytes__())

# correlation table
SCAPY_CORR_ADV = {
    AdvType.ADV_IND: BTLE_ADV_IND,
    AdvType.ADV_NONCONN_IND: BTLE_ADV_NONCONN_IND,
    AdvType.ADV_DIRECT_IND: BTLE_ADV_DIRECT_IND,
    AdvType.ADV_SCAN_IND: BTLE_ADV_SCAN_IND,
    AdvType.ADV_SCAN_RSP: BTLE_SCAN_RSP
}

# correlation table
SCAPY_CORR_ADV_INV = {
    BTLE_ADV_IND: AdvType.ADV_IND,
    BTLE_ADV_NONCONN_IND: AdvType.ADV_NONCONN_IND,
    BTLE_ADV_DIRECT_IND: AdvType.ADV_DIRECT_IND,
    BTLE_ADV_SCAN_IND: AdvType.ADV_SCAN_IND,
    BTLE_SCAN_RSP: AdvType.ADV_SCAN_RSP
}

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

    def to_packet(self):
        """Convert message to the corresponding Scapy packet
        """
        print(self)
        packet = BTLE(access_addr=self.access_address, crc=self.crc)/self.pdu

        # Set packet metadata
        packet.metadata = BLEMetadata()
        packet.metadata.connection_handle = self.conn_handle
        packet.metadata.encrypt = self.encrypt
        packet.metadata.direction = self.direction
        packet.metadata.raw = True

        return packet

    @staticmethod
    def from_packet(packet, encrypt=False):
        """Convert packet to SendBlePdu message.
        """
        direction = packet.metadata.direction
        connection_handle = packet.metadata.connection_handle

        # Extract PDU
        if BTLE_DATA in packet:
            pdu = raw(packet[BTLE_DATA:])
        elif BTLE_CTRL in packet:
            pdu = raw(packet[BTLE_CTRL:])
        elif BTLE_ADV in packet:
            pdu = raw(packet[BTLE_ADV:])
        else:
            return None

        return SendBleRawPdu(
            direction=direction,
            pdu=pdu,
            conn_handle=connection_handle,
            access_address=BTLE(raw(packet)).access_addr,
            crc=BTLE(raw(packet)).crc,
            encrypt=encrypt
        )

@pb_bind(BleDomain, "send_pdu", 1)
class SendBlePdu(PbMessageWrapper):
    """BLE send PDU message class
    """
    direction = PbFieldInt("ble.send_pdu.direction")
    conn_handle = PbFieldInt("ble.send_pdu.conn_handle")
    pdu = PbFieldBytes("ble.send_pdu.pdu")
    encrypt = PbFieldBool("ble.send_pdu.encrypt")

    def to_packet(self):
        """Convert message to the corresponding Scapy packet
        """
        packet = BTLE_DATA(self.pdu)

        # Set packet metadata
        packet.metadata = BLEMetadata()
        packet.metadata.connection_handle = self.conn_handle
        packet.metadata.encrypt = self.encrypt
        packet.metadata.direction = self.direction
        packet.metadata.raw = False

        return packet 

    @staticmethod
    def from_packet(packet, encrypt=False):
        """Convert packet to SendBlePdu message.
        """
        direction = packet.metadata.direction
        connection_handle = packet.metadata.connection_handle

        # Extract PDU
        if BTLE_DATA in packet:
            pdu = packet_to_bytes(packet[BTLE_DATA:])
        elif BTLE_CTRL in packet:
            pdu = packet_to_bytes(packet[BTLE_CTRL:])
        elif BTLE_ADV in packet:
            pdu = packet_to_bytes(packet[BTLE_ADV:])
        else:
            return None

        # Create a SendPdu message
        return SendBlePdu(
            direction=direction,
            conn_handle=connection_handle,
            pdu=pdu,
            encrypt=encrypt
        )



@pb_bind(BleDomain, "adv_pdu", 1)
class BleAdvPduReceived(PbMessageWrapper):
    """BLE advertising PDU received message class
    """
    adv_type = PbFieldInt("ble.adv_pdu.adv_type")
    rssi = PbFieldInt("ble.adv_pdu.rssi")
    bd_address = PbFieldBytes("ble.adv_pdu.bd_address")
    adv_data = PbFieldBytes("ble.adv_pdu.adv_data")
    addr_type = PbFieldInt("ble.adv_pdu.addr_type")


    def to_packet(self):
        """Convert message into its corresponding Scapy packet
        """
        if self.adv_type in SCAPY_CORR_ADV:
            data = bytes(self.adv_data)

            packet = BTLE_ADV()/SCAPY_CORR_ADV[self.adv_type](
                    bytes(self.bd_address) + data
                )

            # Set TxAdd to 1 if address is random
            if self.addr_type == AddressType.RANDOM:
                packet.TxAdd = 1

            # Set packet metadata
            packet.metadata = BLEMetadata()
            packet.metadata.direction = Direction.UNKNOWN
            packet.metadata.rssi = self.rssi
            packet.metadata.raw = False

            # Success, return Scapy packet
            return packet
        else:
            # Unkown advertisement type
            return None

    @staticmethod
    def from_packet(packet):
        """Convert packet into BleAdvPduReceived message
        """
        if BTLE_ADV in packet:
            # Search advertisement type
            for adv_class in SCAPY_CORR_ADV_INV:
                if  packet.haslayer(adv_class):
                    adv_data = b''.join([bytes(x) for x in packet.getlayer(adv_class).data])
                    return BleAdvPduReceived(
                        adv_type=SCAPY_CORR_ADV_INV[adv_class],
                        rssi=packet.metadata.rssi if packet.metadata is not None else 0,
                        bd_address=BDAddress(packet.AdvA).value,
                        adv_data=adv_data,
                        addr_type=AddressType.RANDOM if packet.getlayer(BTLE_ADV).TxAdd == 1 else AddressType.PUBLIC
                    )
        else:
            # Error
            return None


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
        packet.metadata.processed = self.processed
        packet.metadata.raw = False
        return packet

    @staticmethod
    def from_packet(packet):
        """Convert packet into BlePduReceived message
        """
        return BlePduReceived(
            pdu=bytes(packet),
            direction=packet.metadata.direction,
            conn_handle=packet.metadata.connection_handle,
            processed=packet.metadata.processed,
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
        packet.metadata.processed = self.processed
        packet.metadata.raw = True

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
                decrypted=packet.metadata.decrypted,
                processed=packet.metadata.processed
            )

        return None

@pb_bind(BleDomain, "injected", 1)
class Injected(PbMessageWrapper):
    """BLE PDU injected notification message class
    """
    success = PbFieldBool("ble.injected.success")
    access_address = PbFieldInt("ble.injected.access_address")
    injection_attempts = PbFieldInt("ble.injected.injection_attempts")
