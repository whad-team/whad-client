"""ESB Packet translator
"""
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response, ESB_Pseudo_Packet
from whad.esb.metadata import generate_esb_metadata
from whad.protocol.whad_pb2 import Message
import logging

logger = logging.getLogger(__name__)

class ESBMessageTranslator(object):
    """ESB Whad message translator.

    This translator is used to provide the format of a specific scapy packet
    as well as standard methods to convert WHAD ESB messages into scapy packets
    (if it makes sense) and scapy packets into WHAD ESB messages.
    """

    def __init__(self, domain="esb"):
        self.__cached_address = None
        self.__cached_channel = None
        self.__domain = domain

    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        if ESB_Hdr not in packet:
            packet = ESB_Hdr(address=self.__cached_address)/packet

        packet.preamble = 0xAA # force a rebuild
        formatted_packet = ESB_Pseudo_Packet(bytes(packet)[1:])

        timestamp = None
        if hasattr(packet, "metadata"):
            timestamp = packet.metadata.timestamp

        return formatted_packet, timestamp


    def from_message(self, message, msg_type):
        try:
            if msg_type == 'raw_pdu':
                packet = ESB_Hdr(bytes(message.raw_pdu.pdu))
                packet.preamble = 0xAA # force a rebuild

                if ESB_Payload_Hdr not in packet:
                    packet = packet/ESB_Payload_Hdr()/ESB_Ack_Response()

                packet.metadata = generate_esb_metadata(message, msg_type)
                return packet

            elif msg_type == 'pdu':
                packet = ESB_Payload_Hdr(bytes(message.pdu.pdu))
                packet.metadata = generate_esb_metadata(message, msg_type)
                return packet
        except AttributeError:
            return None

    def from_packet(self, packet, channel=None, retransmission_count=1):
        msg = Message()
        if ESB_Hdr in packet:
            getattr(msg, self.__domain).send_raw.channel = channel if channel is not None else 0xFF
            packet.preamble = 0xAA
            getattr(msg, self.__domain).send_raw.pdu = bytes(packet)
            getattr(msg, self.__domain).send_raw.retransmission_count = retransmission_count
        elif ESB_Payload_Hdr in packet:
            getattr(msg, self.__domain).send.channel = channel if channel is not None else 0xFF
            getattr(msg, self.__domain).send.pdu = bytes(packet)
            getattr(msg, self.__domain).send.retransmission_count = retransmission_count

        else:
            msg = None
        return msg
