"""ZigBee Packet translator
"""
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
from whad.scapy.layers.dot15d4tap import Dot15d4TAP_Hdr, Dot15d4TAP_TLV_Hdr, Dot15d4TAP_FCS_Type
from whad.protocol.whad_pb2 import Message
from whad.hub import ProtocolHub
from whad.hub.dot15d4 import RawPduReceived, PduReceived, generate_dot15d4_metadata
from struct import pack
import logging

logger = logging.getLogger(__name__)

class Dot15d4MessageTranslator(object):
    """802.15.4 Whad message translator.

    This translator is used to provide the format of a specific scapy packet
    as well as standard methods to convert WHAD 802.15.4 messages into scapy packets
    (if it makes sense) and scapy packets into WHAD 802.15.4 messages.
    """

    def __init__(self, protocol_hub: ProtocolHub):
        self.__hub = protocol_hub

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

    def from_message(self, message):
        try:
            if isinstance(message, RawPduReceived):
                packet = Dot15d4FCS(bytes(message.pdu) + bytes(pack(">H", message.fcs)))
                packet.metadata = generate_dot15d4_metadata(message)
                return packet

            elif isinstance(message, PduReceived):
                packet = Dot15d4(bytes(message.pdu))
                packet.metadata = generate_dot15d4_metadata(message)
                return packet
        except AttributeError:
            return None


    def from_packet(self, packet, channel=11):
        msg = Message()

        if Dot15d4FCS in packet:
            # Create a SendPdu
            msg = self.__hub.dot15d4.create_send_raw_pdu(
                channel,
                bytes(packet)[:-2],
                packet.fcs
            )
        elif Dot15d4 in packet:
            msg = self.__hub.dot15d4.create_send_pdu(
                channel,
                bytes(packet)
            )
        else:
            # Raw MAC
            msg = self.__hub.dot15d4.create_send_pdu(
                channel,
                bytes(packet)
            )
        return msg
