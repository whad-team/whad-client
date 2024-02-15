"""802.15.4 Packet translator
"""
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
from whad.scapy.layers.dot15d4tap import Dot15d4TAP_Hdr, Dot15d4TAP_TLV_Hdr, Dot15d4TAP_FCS_Type
from whad.dot15d4.metadata import generate_dot15d4_metadata
from whad.protocol.whad_pb2 import Message
from typing import Union, Tuple
from struct import pack
import logging

logger = logging.getLogger(__name__)

class Dot15d4MessageTranslator(object):
    """802.15.4 Whad message translator.

    This translator is used to provide the format of a specific scapy packet
    as well as standard methods to convert WHAD 802.15.4 messages into scapy packets
    (if it makes sense) and scapy packets into WHAD 802.15.4 messages.
    """

    def format(self, packet:Dot15d4FCS) -> Tuple[Dot15d4TAP_Hdr, int]:
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
            fcs_type = int(Dot15d4FCS in packet)
            )
        )
        formatted_packet = header/packet
        return formatted_packet, timestamp

    def from_message(self, message:Message, msg_type:str) -> Union[Dot15d4, Dot15d4FCS, None]:
        try:
            if msg_type == 'raw_pdu':
                packet = Dot15d4FCS(bytes(message.raw_pdu.pdu) + bytes(pack("<H", message.raw_pdu.fcs)))
                packet.metadata = generate_dot15d4_metadata(message, msg_type)
                return packet

            elif msg_type == 'pdu':
                packet = Dot15d4(bytes(message.pdu.pdu))
                packet.metadata = generate_dot15d4_metadata(message, msg_type)
                return packet
        except AttributeError:
            return None


    def from_packet(self, packet:Union[Dot15d4, Dot15d4FCS, bytes], channel:int = 11) -> Message:
        msg = Message()

        if Dot15d4FCS in packet:
            msg.dot15d4.send_raw.channel = channel
            pdu = bytes(packet)[:-2]
            msg.dot15d4.send_raw.pdu = pdu
            msg.dot15d4.send_raw.fcs = packet.fcs

        elif Dot15d4 in packet:
            msg.dot15d4.send.channel = channel
            pdu = bytes(packet)
            msg.dot15d4.send.pdu = pdu
        else:
            # Raw MAC
            msg.dot15d4.send.channel = channel
            pdu = bytes(packet)
            msg.dot15d4.send.pdu = pdu
        return msg
