"""WHAD Protocol Logitech Unifying PDU messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response, ESB_Pseudo_Packet
from ..message import pb_bind, PbFieldBytes, PbFieldBool, PbFieldInt, PbMessageWrapper
from whad.hub.message import AbstractPacket
from . import UnifyingDomain, UnifyingMetadata


@pb_bind(UnifyingDomain, 'send', 1)
class SendPdu(PbMessageWrapper):
    """ESB SendPdu message
    """

    channel = PbFieldInt('unifying.send.channel')
    pdu = PbFieldBytes('unifying.send.pdu')
    retr_count = PbFieldInt('unifying.send.retransmission_count')

    def to_packet(self):
        """Convert SendPdu message to its scapy equivalent
        """
        return ESB_Payload_Hdr(bytes(self.pdu))

    @staticmethod
    def from_packet(packet, retr_count: int = 1):
        """Convert scapy packet to SendPdu message.
        """
        return SendPdu(
            channel=packet.metadata.channel,
            pdu=bytes(packet),
            retr_count=retr_count
        )

@pb_bind(UnifyingDomain, 'send_raw', 1)
class SendRawPdu(PbMessageWrapper):
    """ESB SendRawPdu message
    """

    channel = PbFieldInt('unifying.send_raw.channel')
    pdu = PbFieldBytes('unifying.send_raw.pdu')
    retr_count = PbFieldInt('unifying.send_raw.retransmission_count')

    def to_packet(self):
        """Convert SendPdu message to its scapy equivalent
        """
        packet = ESB_Hdr(bytes(self.pdu))
        packet.preamble = 0xAA
        return packet


    @staticmethod
    def from_packet(packet, retr_count: int = 1):
        """Convert scapy packet to SendPdu message.
        """
        return SendRawPdu(
            channel=packet.metadata.channel,
            pdu=bytes(packet),
            retr_count=retr_count
        )

@pb_bind(UnifyingDomain, 'pdu', 1)
class PduReceived(PbMessageWrapper):
    """ESB PduReceived message
    """

    channel = PbFieldInt('unifying.pdu.channel')
    pdu = PbFieldBytes('unifying.pdu.pdu')
    rssi = PbFieldInt('unifying.pdu.rssi', optional=True)
    timestamp = PbFieldInt('unifying.pdu.timestamp', optional=True)
    crc_validity = PbFieldBool('unifying.pdu.crc_validity', optional=True)
    address = PbFieldBytes('unifying.pdu.address', optional=True)

    def to_packet(self):
        """Convert message to the corresponding scapy packet
        """
        packet = ESB_Payload_Hdr(bytes(self.pdu))
        packet.metadata = UnifyingMetadata()
        packet.metadata.channel = self.channel
        packet.metadata.raw = False

        packet.metadata.decrypted = False
        if self.rssi is not None:
            packet.metadata.rssi = self.rssi
        if self.timestamp is not None:
            packet.metadata.timestamp = self.timestamp
        if self.crc_validity is not None:
            packet.metadata.is_crc_valid = self.crc_validity
        if self.address is not None:
            packet.metadata.address = ":".join(["{:02x}".format(i) for i in self.address])
        return packet

    @staticmethod
    def from_packet(packet):
        """Convert scapy packet to PduReceived message
        """
        msg = PduReceived(
            channel=packet.metadata.channel,
            pdu=bytes(packet)
        )

        # Set message fields based on packet metadata
        if packet.metadata.decrypted is not None:
            msg.decrypted = packet.metadata.decrypted
        if packet.metadata.rssi is not None:
            msg.rssi = packet.metadata.rssi
        if packet.metadata.timestamp is not None:
            msg.timestamp = packet.metadata.timestamp
        if packet.metadata.is_crc_valid is not None:
            msg.crc_validity = packet.metadata.is_crc_valid
        if packet.metadata.address is not None:
            msg.address = bytes.fromhex(packet.metadata.address.replace(':', ''))

        return msg

@pb_bind(UnifyingDomain, 'raw_pdu', 1)
class RawPduReceived(PbMessageWrapper):
    """ESB RawPduReceived message
    """

    channel = PbFieldInt('unifying.raw_pdu.channel')
    pdu = PbFieldBytes('unifying.raw_pdu.pdu')
    rssi = PbFieldInt('unifying.raw_pdu.rssi', optional=True)
    timestamp = PbFieldInt('unifying.raw_pdu.timestamp', optional=True)
    crc_validity = PbFieldBool('unifying.raw_pdu.crc_validity', optional=True)
    address = PbFieldBytes('unifying.raw_pdu.address', optional=True)

    def to_packet(self):
        """Convert message to the corresponding scapy packet
        """
        packet = ESB_Hdr(bytes(self.pdu))
        packet.metadata = UnifyingMetadata()
        packet.metadata.channel = self.channel
        packet.metadata.raw = True

        packet.metadata.decrypted = False

        if self.rssi is not None:
            packet.metadata.rssi = self.rssi
        if self.timestamp is not None:
            packet.metadata.timestamp = self.timestamp
        if self.crc_validity is not None:
            packet.metadata.is_crc_valid = self.crc_validity
        if self.address is not None:
            packet.metadata.address = ":".join(["{:02x}".format(i) for i in self.address])
        return packet

    @staticmethod
    def from_packet(packet):
        """Convert scapy packet to RawPduReceived message
        """
        # Force packet preamble to 0xAA
        packet.preamble = 0xAA

        msg = RawPduReceived(
            channel=packet.metadata.channel,
            pdu=bytes(packet)
        )

        # Set message fields based on packet metadata

        if packet.metadata.decrypted is not None:
            msg.decrypted = packet.metadata.decrypted
        if packet.metadata.rssi is not None:
            msg.rssi = packet.metadata.rssi
        if packet.metadata.timestamp is not None:
            msg.timestamp = packet.metadata.timestamp
        if packet.metadata.is_crc_valid is not None:
            msg.crc_validity = packet.metadata.is_crc_valid
        if packet.metadata.address is not None:
            msg.address = bytes.fromhex(packet.metadata.address.replace(':', ''))

        return msg
