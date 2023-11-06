"""BLE Packet translator
"""
import struct
import logging

from scapy.compat import raw
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA, BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP, \
    BTLE_RF, BTLE_CTRL

from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import BleAdvType
from whad.ble.metadata import generate_ble_metadata

logger = logging.getLogger(__name__)

def packet_to_bytes(packet):
    """Convert packet to bytes
    """
    try:
        return raw(packet)
    except TypeError as type_err:
        return bytes(packet.__bytes__())

class BleMessageTranslator(object):
    """BLE Whad message translator.

    This translator is used to provide the format of a specific scapy packet
    as well as standard methods to convert WHAD BLE messages into scapy packets
    (if it makes sense) and scapy packets into WHAD BLE messages.
    """

    # correlation table
    SCAPY_CORR_ADV = {
        BleAdvType.ADV_IND: BTLE_ADV_IND,
        BleAdvType.ADV_NONCONN_IND: BTLE_ADV_NONCONN_IND,
        BleAdvType.ADV_DIRECT_IND: BTLE_ADV_DIRECT_IND,
        BleAdvType.ADV_SCAN_IND: BTLE_ADV_SCAN_IND,
        BleAdvType.ADV_SCAN_RSP: BTLE_SCAN_RSP
    }

    def __init__(self):
        self.__access_address = 0x11223344


    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        formatted_packet = packet
        if BTLE not in packet:
            if BTLE_ADV in packet:
                formatted_packet = BTLE(access_addr=0x8e89bed6)/packet
            elif BTLE_DATA in packet:
                # We are forced to use a pseudo access address for connections in this case.
                formatted_packet = BTLE(access_addr=self.__access_address) / packet

        timestamp = None
        if hasattr(packet, "metadata"):
            header, timestamp = packet.metadata.convert_to_header()
            formatted_packet = header / formatted_packet
        else:
            header = BTLE_RF()
            formatted_packet = header / formatted_packet

        return formatted_packet, timestamp


    def from_message(self, message, msg_type):
        """Convert a WHAD message into a packet, if it makes sense.
        """
        try:
            # Advertising PDU (RX)
            if msg_type == 'adv_pdu':
                if message.adv_pdu.adv_type in BleMessageTranslator.SCAPY_CORR_ADV:
                    data = bytes(message.adv_pdu.adv_data)

                    packet = BTLE_ADV()/BleMessageTranslator.SCAPY_CORR_ADV[message.adv_pdu.adv_type](
                            bytes(message.adv_pdu.bd_address) + data
                        )
                    packet.metadata = generate_ble_metadata(message, msg_type)
                    return packet

            # Raw PDU (RX)
            elif msg_type == 'raw_pdu':
                packet = BTLE(bytes(struct.pack("I", message.raw_pdu.access_address)) + bytes(message.raw_pdu.pdu) + bytes(struct.pack(">I", message.raw_pdu.crc)[1:]))
                packet.metadata = generate_ble_metadata(message, msg_type)
                return packet

            # Normal PDU (RX)
            elif msg_type == 'pdu':
                packet = BTLE_DATA(message.pdu.pdu)
                packet.metadata = generate_ble_metadata(message, msg_type)
                return packet

            # Send PDU (TX)
            elif msg_type == 'send_pdu':
                packet = BTLE_DATA(message.send_pdu.pdu)
                packet.metadata = generate_ble_metadata(message, msg_type)
                return packet

            # Send Raw PDU (TX)
            elif msg_type == 'send_raw_pdu':
                packet = BTLE(bytes(struct.pack("I", message.send_raw_pdu.access_address)) + bytes(message.send_raw_pdu.pdu) + bytes(struct.pack(">I", message.send_raw_pdu.crc)[1:]))
                packet.metadata = generate_ble_metadata(message, msg_type)
                return packet

        except AttributeError as err:
            logger.error(err)
            return None


    def from_packet(self, packet, encrypt=False):
        msg = Message()
        direction = packet.metadata.direction
        connection_handle = packet.metadata.connection_handle

        if BTLE in packet:
            msg.ble.send_raw_pdu.direction = direction
            msg.ble.send_raw_pdu.conn_handle = connection_handle
            msg.ble.send_raw_pdu.crc = BTLE(raw(packet)).crc # force the CRC to be generated if not provided
            msg.ble.send_raw_pdu.access_address = BTLE(raw(packet)).access_addr

            msg.ble.send_raw_pdu.encrypt = encrypt

            if BTLE_DATA in packet:
                msg.ble.send_raw_pdu.pdu = raw(packet[BTLE_DATA:])
            elif BTLE_CTRL in packet:
                msg.ble.send_raw_pdu.pdu = raw(packet[BTLE_CTRL:])
            elif BTLE_ADV in packet:
                msg.ble.send_raw_pdu.pdu = raw(packet[BTLE_ADV:])
            else:
                return None

        else:
            msg.ble.send_pdu.direction = direction
            msg.ble.send_pdu.conn_handle = connection_handle
            msg.ble.send_pdu.encrypt = encrypt
            if BTLE_DATA in packet:
                msg.ble.send_pdu.pdu = packet_to_bytes(packet[BTLE_DATA:])
            elif BTLE_CTRL in packet:
                msg.ble.send_pdu.pdu = packet_to_bytes(packet[BTLE_CTRL:])
            elif BTLE_ADV in packet:
                msg.ble.send_pdu.pdu = packet_to_bytes(packet[BTLE_ADV:])
            else:
                return None

        return msg