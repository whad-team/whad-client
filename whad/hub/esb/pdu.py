"""WHAD Protocol ESB PDU messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response, ESB_Pseudo_Packet
from ..message import pb_bind, PbFieldBytes, PbFieldBool, PbFieldInt, PbMessageWrapper
from whad.hub.message import AbstractPacket
from . import EsbDomain, ESBMetadata

@pb_bind(EsbDomain, 'send', 1)
class SendPdu(PbMessageWrapper):
    """ESB SendPdu message
    """

    channel = PbFieldInt('esb.send.channel')
    pdu = PbFieldBytes('esb.send.pdu')
    retr_count = PbFieldInt('esb.send.retransmission_count')

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

@pb_bind(EsbDomain, 'send_raw', 1)
class SendRawPdu(PbMessageWrapper):
    """ESB SendRawPdu message
    """

    channel = PbFieldInt('esb.send_raw.channel')
    pdu = PbFieldBytes('esb.send_raw.pdu')
    retr_count = PbFieldInt('esb.send_raw.retransmission_count')

    def to_packet(self):
        """Convert SendPdu message to its scapy equivalent
        """
        packet = ESB_Hdr(bytes(self.pdu))
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

@pb_bind(EsbDomain, 'pdu', 1)
class PduReceived(PbMessageWrapper):
    """ESB PduReceived message
    """

    channel = PbFieldInt('esb.pdu.channel')
    pdu = PbFieldBytes('esb.pdu.pdu')
    rssi = PbFieldInt('esb.pdu.rssi', optional=True)
    timestamp = PbFieldInt('esb.pdu.timestamp', optional=True)
    crc_validity = PbFieldBool('esb.pdu.crc_validity', optional=True)
    address = PbFieldBytes('esb.pdu.address', optional=True)

    def to_packet(self):
        """Convert message to the corresponding scapy packet
        """
        packet = ESB_Payload_Hdr(bytes(self.pdu))
        packet.metadata = ESBMetadata()
        packet.metadata.channel = self.channel
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
        if packet.metadata.rssi is not None:
            msg.rssi = packet.metadata.rssi
        if packet.metadata.timestamp is not None:
            msg.timestamp = packet.metadata.timestamp
        if packet.metadata.is_crc_valid is not None:
            msg.crc_validity = packet.metadata.is_crc_valid
        if packet.metadata.address is not None:
            msg.address = bytes.fromhex(packet.metadata.address.replace(':', ''))

        return msg

@pb_bind(EsbDomain, 'raw_pdu', 1)
class RawPduReceived(PbMessageWrapper):
    """ESB RawPduReceived message
    """

    channel = PbFieldInt('esb.raw_pdu.channel')
    pdu = PbFieldBytes('esb.raw_pdu.pdu')
    rssi = PbFieldInt('esb.raw_pdu.rssi', optional=True)
    timestamp = PbFieldInt('esb.raw_pdu.timestamp', optional=True)
    crc_validity = PbFieldBool('esb.raw_pdu.crc_validity', optional=True)
    address = PbFieldBytes('esb.raw_pdu.address', optional=True)

    def to_packet(self):
        """Convert message to the corresponding scapy packet
        """
        packet = ESB_Hdr(bytes(self.pdu))
        packet.metadata = ESBMetadata()
        packet.metadata.raw = True
        packet.metadata.decrypted = False
        packet.metadata.channel = self.channel
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
        msg = RawPduReceived(
            channel=packet.metadata.channel,
            pdu=bytes(packet)
        )

        # Set message fields based on packet metadata
        if packet.metadata.rssi is not None:
            msg.rssi = packet.metadata.rssi
        if packet.metadata.timestamp is not None:
            msg.timestamp = packet.metadata.timestamp
        if packet.metadata.is_crc_valid is not None:
            msg.crc_validity = packet.metadata.is_crc_valid
        if packet.metadata.address is not None:
            msg.address = bytes.fromhex(packet.metadata.address.replace(':', ''))

        return msg
