"""ZigBee Packet translator
"""
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
from whad.scapy.layers.dot15d4tap import Dot15d4TAP_Hdr, Dot15d4TAP_TLV_Hdr, Dot15d4TAP_FCS_Type
from whad.zigbee.metadata import generate_zigbee_metadata
from whad.protocol.whad_pb2 import Message
from struct import pack
import logging

logger = logging.getLogger(__name__)

class ZigbeeMessageTranslator(object):
    """Zigbee Whad message translator.

    This translator is used to provide the format of a specific scapy packet
    as well as standard methods to convert WHAD Zigbee messages into scapy packets
    (if it makes sense) and scapy packets into WHAD Zigbee messages.
    """

    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        if hasattr(packet, "metadata"):
            header, timestamp = packet.metadata.convert_to_header()
        else:
            header = Dot15d4TAP_Hdr()
            timestamp = None

        header.data.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_FCS_Type(
            fcs_type=int(Dot15d4FCS in packet)
            )
        )
        formatted_packet = header/packet
        return formatted_packet, timestamp

    def from_message(self, message, msg_type):
        try:
            if msg_type == 'raw_pdu':
                packet = Dot15d4FCS(bytes(message.raw_pdu.pdu) + bytes(pack(">H", message.raw_pdu.fcs)))
                packet.metadata = generate_zigbee_metadata(message, msg_type)
                return packet

            elif msg_type == 'pdu':
                packet = Dot15d4(bytes(message.pdu.pdu))
                packet.metadata = generate_zigbee_metadata(message, msg_type)
                return packet
        except AttributeError:
            return None


    def from_packet(self, packet, channel=11):
        msg = Message()

        if Dot15d4FCS in packet:
            msg.zigbee.send_raw.channel = channel
            pdu = bytes(packet)[:-2]
            msg.zigbee.send_raw.pdu = pdu
            msg.zigbee.send_raw.fcs = packet.fcs

        elif Dot15d4 in packet:
            msg.zigbee.send.channel = channel
            pdu = bytes(packet)
            msg.zigbee.send.pdu = pdu
        else:
            msg = None

        return msg
