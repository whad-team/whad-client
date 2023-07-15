"""Phy Packet translator
"""
from whad.scapy.layers.phy import Phy_Packet
from whad.phy.metadata import generate_phy_metadata
from whad.protocol.whad_pb2 import Message
import logging

logger = logging.getLogger(__name__)

class PhyMessageTranslator(object):
    """Phy Whad message translator.

    This translator is used to provide the format of a specific scapy packet
    as well as standard methods to convert WHAD Phy messages into scapy packets
    (if it makes sense) and scapy packets into WHAD Phy messages.
    """

    def __init__(self):
        # Address cache
        self.address = None
        self.pattern_cropped_bytes = 0
        self.pattern = None

        self.physical_layer = None

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
        if msg_type == 'raw_packet':
            bytes_packet = bytes(message.raw_packet.packet)
            if self.pattern_cropped_bytes > 0:
                bytes_packet = self.pattern[:self.pattern_cropped_bytes] + bytes_packet

            if self.physical_layer is not None and self.physical_layer.decoding is not None:
                bytes_packet = self.physical_layer.decoding(bytes_packet, self.physical_layer.configuration)

            if self.physical_layer is not None and self.physical_layer.decoding is not None:
                packet = self.physical_layer.scapy_layer(bytes_packet)
            else:
                packet = Phy_Packet(bytes_packet)

            packet.metadata = generate_phy_metadata(message, msg_type)

            return packet

        elif msg_type == 'packet':
            bytes_packet = bytes(message.packet.packet)
            if self.pattern_cropped_bytes > 0:

                bytes_packet = self.pattern[:self.pattern_cropped_bytes] + bytes_packet
            if self.physical_layer is not None and self.physical_layer.decoding is not None:
                bytes_packet = self.physical_layer.decoding(bytes_packet, self.physical_layer.configuration)
            if self.physical_layer is not None and self.physical_layer.decoding is not None:
                packet = self.physical_layer.scapy_layer(bytes_packet)
            else:
                packet = Phy_Packet(bytes_packet)

            packet.metadata = generate_phy_metadata(message, msg_type)


            return packet


    def from_packet(self, packet):
        msg = Message()
        if Phy_Packet in packet or isinstance(packet, bytes):
            msg.phy.send.packet = bytes(packet)

        elif isinstance(packet, list) and len(packet) % 2 == 0:
            msg.phy.send_raw.iq = bytes(packet)
        else:
            msg = None
        return msg
