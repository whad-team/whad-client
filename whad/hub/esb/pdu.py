"""WHAD Protocol ESB PDU messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response, ESB_Pseudo_Packet
from ..message import pb_bind, PbFieldBytes, PbFieldBool, PbFieldInt, PbMessageWrapper, PbPacketMessageWrapper
from . import EsbDomain

@pb_bind(EsbDomain, 'send', 1)
class SendPdu(PbPacketMessageWrapper):
    """ESB SendPdu message
    """

    channel = PbFieldInt('esb.send.channel')
    pdu = PbFieldBytes('esb.send.pdu')
    retr_count = PbFieldInt('esb.send.retransmission_count')

    def to_scapy(self):
        packet = ESB_Payload_Hdr(bytes(self.pdu))
        packet.metadata = generate_esb_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        return cls(
            pdu = bytes(packet),
            channel = packet.metadata.channel
        )

@pb_bind(EsbDomain, 'send_raw', 1)
class SendRawPdu(PbPacketMessageWrapper):
    """ESB SendRawPdu message
    """

    channel = PbFieldInt('esb.send_raw.channel')
    pdu = PbFieldBytes('esb.send_raw.pdu')
    retr_count = PbFieldInt('esb.send_raw.retransmission_count')

    def to_scapy(self):
        packet = ESB_Hdr(self.pdu)
        packet.metadata = generate_esb_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        return cls(
            pdu = bytes(packet),
            channel = packet.metadata.channel
        )

@pb_bind(EsbDomain, 'pdu', 1)
class PduReceived(PbPacketMessageWrapper):
    """ESB PduReceived message
    """

    channel = PbFieldInt('esb.pdu.channel')
    pdu = PbFieldBytes('esb.pdu.pdu')
    rssi = PbFieldInt('esb.pdu.rssi', optional=True)
    timestamp = PbFieldInt('esb.pdu.timestamp', optional=True)
    crc_validity = PbFieldBool('esb.pdu.crc_validity', optional=True)
    address = PbFieldBytes('esb.pdu.address', optional=True)


    def to_scapy(self):
        from whad.esb.metadata import generate_esb_metadata
        packet = ESB_Payload_Hdr(bytes(self.pdu))
        packet.metadata = generate_esb_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        return cls(
            channel = packet.metadata.channel,
            pdu = bytes(packet),
            timestamp = packet.metadata.timestamp,
            crc_validity = packet.metadata.is_crc_valid,
            address = bytes.fromhex(packet.metadata.address.replace(":", ""))
        )

@pb_bind(EsbDomain, 'raw_pdu', 1)
class RawPduReceived(PbPacketMessageWrapper):
    """ESB RawPduReceived message
    """

    channel = PbFieldInt('esb.raw_pdu.channel')
    pdu = PbFieldBytes('esb.raw_pdu.pdu')
    rssi = PbFieldInt('esb.raw_pdu.rssi', optional=True)
    timestamp = PbFieldInt('esb.raw_pdu.timestamp', optional=True)
    crc_validity = PbFieldBool('esb.raw_pdu.crc_validity', optional=True)
    address = PbFieldBytes('esb.raw_pdu.address', optional=True)

    def to_scapy(self):
        from whad.esb.metadata import generate_esb_metadata
        packet = ESB_Hdr(bytes(self.pdu))
        packet.preamble = 0xAA # force a rebuild

        if ESB_Payload_Hdr not in packet:
            packet = packet/ESB_Payload_Hdr()/ESB_Ack_Response()

        packet.metadata = generate_esb_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        return cls(
            channel = packet.metadata.channel,
            pdu = bytes(packet),
            timestamp = packet.metadata.timestamp,
            crc_validity = packet.metadata.is_crc_valid,
            address = bytes.fromhex(packet.metadata.address.replace(":", ""))
        )
