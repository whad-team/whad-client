"""BLE Packet translator
"""
import struct
import logging
from whad.helpers import swap_bits
from scapy.compat import raw
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA, BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP, \
    BTLE_RF, BTLE_CTRL

from whad.hub.ble import generate_ble_metadata
from whad.hub import ProtocolHub
from whad.hub.ble import AdvType, BleAdvPduReceived, BlePduReceived, BleRawPduReceived, \
    SendBlePdu, SendBleRawPdu

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
        AdvType.ADV_IND: BTLE_ADV_IND,
        AdvType.ADV_NONCONN_IND: BTLE_ADV_NONCONN_IND,
        AdvType.ADV_DIRECT_IND: BTLE_ADV_DIRECT_IND,
        AdvType.ADV_SCAN_IND: BTLE_ADV_SCAN_IND,
        AdvType.ADV_SCAN_RSP: BTLE_SCAN_RSP
    }

    def __init__(self, protocol_hub: ProtocolHub):
        self.__access_address = 0x11223344
        self.__hub = protocol_hub


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


    def from_message(self, message):
        """Convert a WHAD message into a packet, if it makes sense.
        """
        try:
            # Advertising PDU (RX)
            if isinstance(message, BleAdvPduReceived):
                if message.adv_type in BleMessageTranslator.SCAPY_CORR_ADV:
                    data = bytes(message.adv_data)

                    packet = BTLE_ADV()/BleMessageTranslator.SCAPY_CORR_ADV[message.adv_type](
                            bytes(message.bd_address) + data
                        )
                    packet.metadata = generate_ble_metadata(message)
                    return packet

            # Raw PDU (RX)
            elif isinstance(message, BleRawPduReceived):
                packet = BTLE(bytes(struct.pack("I", message.access_address)) + bytes(message.pdu) + bytes(struct.pack(">I", message.crc)[1:]))
                packet.metadata = generate_ble_metadata(message)
                return packet

            # Normal PDU (RX)
            elif isinstance(message, BlePduReceived):
                packet = BTLE_DATA(message.pdu)
                packet.metadata = generate_ble_metadata(message)
                return packet

            # Send PDU (TX)
            elif isinstance(message, SendBlePdu):
                packet = BTLE_DATA(message.pdu)
                packet.metadata = generate_ble_metadata(message)
                return packet

            # Send Raw PDU (TX)
            elif isinstance(message, SendBleRawPdu):
                packet = BTLE(bytes(struct.pack("I", message.access_address)) + bytes(message.pdu) + bytes(struct.pack(">I", message.crc)[1:]))
                packet.metadata = generate_ble_metadata(message)
                return packet

        except AttributeError as err:
            logger.error(err)
            return None


    def from_packet(self, packet, encrypt=False):
        direction = packet.metadata.direction
        connection_handle = packet.metadata.connection_handle

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

            # Create SendRawPdu message
            msg = self.__hub.ble.create_send_raw_pdu(
                direction,
                pdu,
                crc=BTLE(raw(packet)).crc, # force the CRC to be generated if not provided
                access_address=BTLE(raw(packet)).access_addr,
                conn_handle=connection_handle,
                encrypt=encrypt
            )

        else:

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
            msg = self.__hub.ble.create_send_pdu(
                direction,
                pdu,
                connection_handle,
                encrypt=encrypt
            )

        return msg
