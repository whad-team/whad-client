"""WHAD Protocol Logitech Unifying PDU messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from ..message import pb_bind, PbFieldBytes, PbFieldBool, PbFieldInt, PbMessageWrapper, \
    PbPacketMessageWrapper
from . import UnifyingDomain
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response, ESB_Pseudo_Packet
from whad.scapy.layers.unifying import bind

@pb_bind(UnifyingDomain, 'send', 1)
class SendPdu(PbPacketMessageWrapper):
    """ESB SendPdu message
    """

    channel = PbFieldInt('unifying.send.channel')
    pdu = PbFieldBytes('unifying.send.pdu')
    retr_count = PbFieldInt('unifying.send.retransmission_count')

    def to_scapy(self):
        bind()
        packet = ESB_Payload_Hdr(bytes(self.pdu))
        packet.metadata = generate_esb_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        bind()
        return cls(
            pdu = bytes(packet),
            channel = packet.metadata.channel
        )

@pb_bind(UnifyingDomain, 'send_raw', 1)
class SendRawPdu(PbPacketMessageWrapper):
    """ESB SendRawPdu message
    """

    channel = PbFieldInt('unifying.send_raw.channel')
    pdu = PbFieldBytes('unifying.send_raw.pdu')
    retr_count = PbFieldInt('unifying.send_raw.retransmission_count')

    def to_scapy(self):
        bind()
        packet = ESB_Hdr(self.pdu)
        packet.metadata = generate_esb_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        bind()
        return cls(
            pdu = bytes(packet),
            channel = packet.metadata.channel
        )


@pb_bind(UnifyingDomain, 'pdu', 1)
class PduReceived(PbPacketMessageWrapper):
    """ESB PduReceived message
    """

    channel = PbFieldInt('unifying.pdu.channel')
    pdu = PbFieldBytes('unifying.pdu.pdu')
    rssi = PbFieldInt('unifying.pdu.rssi', optional=True)
    timestamp = PbFieldInt('unifying.pdu.timestamp', optional=True)
    crc_validity = PbFieldBool('unifying.pdu.crc_validity', optional=True)
    address = PbFieldBytes('unifying.pdu.address', optional=True)


    def to_scapy(self):
        from whad.esb.metadata import generate_esb_metadata
        bind()
        packet = ESB_Payload_Hdr(bytes(self.pdu))
        packet.metadata = generate_esb_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        bind()
        return cls(
            channel = packet.metadata.channel,
            pdu = bytes(packet),
            timestamp = packet.metadata.timestamp,
            crc_validity = packet.metadata.is_crc_valid,
            address = bytes.fromhex(packet.metadata.address.replace(":", ""))
        )


@pb_bind(UnifyingDomain, 'raw_pdu', 1)
class RawPduReceived(PbPacketMessageWrapper):
    """ESB RawPduReceived message
    """

    channel = PbFieldInt('unifying.raw_pdu.channel')
    pdu = PbFieldBytes('unifying.raw_pdu.pdu')
    rssi = PbFieldInt('unifying.raw_pdu.rssi', optional=True)
    timestamp = PbFieldInt('unifying.raw_pdu.timestamp', optional=True)
    crc_validity = PbFieldBool('unifying.raw_pdu.crc_validity', optional=True)
    address = PbFieldBytes('unifying.raw_pdu.address', optional=True)

    def to_scapy(self):
        from whad.esb.metadata import generate_esb_metadata
        bind()
        packet = ESB_Hdr(bytes(self.pdu))
        packet.preamble = 0xAA # force a rebuild

        if ESB_Payload_Hdr not in packet:
            packet = packet/ESB_Payload_Hdr()/ESB_Ack_Response()

        packet.metadata = generate_esb_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        bind()
        return cls(
            channel = packet.metadata.channel,
            pdu = bytes(packet),
            timestamp = packet.metadata.timestamp,
            crc_validity = packet.metadata.is_crc_valid,
            address = bytes.fromhex(packet.metadata.address.replace(":", ""))
        )
