"""ESB Packet translator
"""
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response, ESB_Pseudo_Packet
from whad.hub.esb import generate_esb_metadata
from whad.protocol.whad_pb2 import Message
from whad.hub import ProtocolHub
from whad.hub.esb import RawPduReceived as EsbRawPduReceived, PduReceived as EsbPduReceived
from whad.hub.unifying import RawPduReceived as UniRawPduReceived, PduReceived as UniPduReceived
import logging

logger = logging.getLogger(__name__)

class ESBMessageTranslator(object):
    """ESB Whad message translator.

    This translator is used to provide the format of a specific scapy packet
    as well as standard methods to convert WHAD ESB messages into scapy packets
    (if it makes sense) and scapy packets into WHAD ESB messages.
    """

    def __init__(self, domain="esb", protocol_hub: ProtocolHub=None):
        self.__cached_address = None
        self.__cached_channel = None
        self.__domain = domain
        self.__hub = protocol_hub

    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        if ESB_Hdr not in packet:
            packet = ESB_Hdr(address=self.__cached_address)/packet

        packet.preamble = 0xAA # force a rebuild
        formatted_packet = ESB_Pseudo_Packet(bytes(packet))

        timestamp = None
        if hasattr(packet, "metadata"):
            timestamp = packet.metadata.timestamp

        return formatted_packet, timestamp


    def from_message(self, message):
        try:
            if isinstance(message, EsbRawPduReceived) or isinstance(message, UniRawPduReceived):
                packet = ESB_Hdr(bytes(message.pdu))
                packet.preamble = 0xAA # force a rebuild

                if ESB_Payload_Hdr not in packet:
                    packet = packet/ESB_Payload_Hdr()/ESB_Ack_Response()

                packet.metadata = generate_esb_metadata(message)
                return packet

            elif isinstance(message, EsbPduReceived) or isinstance(message, UniPduReceived):
                packet = ESB_Payload_Hdr(bytes(message.pdu))
                packet.metadata = generate_esb_metadata(message)
                return packet
        except AttributeError:
            return None

    def from_packet(self, packet, channel=None, retransmission_count=1):
        if ESB_Hdr in packet:
            # Force packet preamble to 0xAA
            packet.preamble = 0xAA

            # Create a SendRawPdu message
            msg = self.__hub.get(self.__domain).create_send_raw_pdu(
                channel if channel is not None else 0xFF,
                bytes(packet),
                retransmission_count
            )
        elif ESB_Payload_Hdr in packet:
            # Create a SendPdu message
            msg = self.__hub.get(self.__domain).create_send_pdu(
                channel if channel is not None else 0xFF,
                bytes(packet),
                retransmission_count
            )
        else:
            msg = None
        return msg
