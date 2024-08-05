"""Phy Packet translator
"""
from whad.scapy.layers.phy import Phy_Packet_Hdr, Phy_Packet
from whad.protocol.whad_pb2 import Message
from whad.hub import ProtocolHub
from whad.hub.phy import PacketReceived, RawPacketReceived, generate_phy_metadata
import logging

logger = logging.getLogger(__name__)

class PhyMessageTranslator(object):
    """Phy Whad message translator.

    This translator is used to provide the format of a specific scapy packet
    as well as standard methods to convert WHAD Phy messages into scapy packets
    (if it makes sense) and scapy packets into WHAD Phy messages.
    """

    def __init__(self, protocol_hub: ProtocolHub):
        # Address cache
        self.address = None
        self.pattern_cropped_bytes = 0
        self.pattern = None

        self.physical_layer = None

        self.__hub = protocol_hub

    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        return Phy_Packet_Hdr(rssi=packet.metadata.rssi, frequency=packet.metadata.frequency) / packet, None


    def from_message(self, message):
        if isinstance(message, RawPacketReceived):
            bytes_packet = bytes(message.packet)
            if self.pattern_cropped_bytes > 0:
                bytes_packet = self.pattern[:self.pattern_cropped_bytes] + bytes_packet

            if self.physical_layer is not None and self.physical_layer.decoding is not None:
                bytes_packet = self.physical_layer.decoding(bytes_packet, self.physical_layer.configuration)
            if bytes_packet is not None and len(bytes_packet) > 0:
                if self.physical_layer is not None and self.physical_layer.scapy_layer is not None:
                    packet = self.physical_layer.scapy_layer(bytes_packet)
                else:
                    packet = Phy_Packet(bytes_packet)
                    packet.metadata = generate_phy_metadata(message)

                return packet

        elif isinstance(message, PacketReceived):
            bytes_packet = bytes(message.packet)
            if self.pattern_cropped_bytes > 0:

                bytes_packet = self.pattern[:self.pattern_cropped_bytes] + bytes_packet
            if self.physical_layer is not None and self.physical_layer.decoding is not None:
                bytes_packet = self.physical_layer.decoding(bytes_packet, self.physical_layer.configuration)
            if bytes_packet is not None and len(bytes_packet) > 0:
                if self.physical_layer is not None and self.physical_layer.scapy_layer is not None:
                    packet = self.physical_layer.scapy_layer(bytes_packet)
                else:
                    packet = Phy_Packet(bytes_packet)
                    packet.metadata = generate_phy_metadata(message)
                return packet


    def from_packet(self, packet):
        if Phy_Packet in packet or isinstance(packet, bytes):
            msg = self.__hub.phy.create_send_packet(bytes(packet))
        elif isinstance(packet, list) and len(packet) % 2 == 0:
            msg = self.__hub.phy.create_send_raw_packet(packet)
        else:
            msg = None
        return msg
