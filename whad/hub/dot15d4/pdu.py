"""WHAD Protocol Dot15d4 pdu messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.hub.message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper, \
    PbFieldBool, PbPacketMessageWrapper
from whad.hub.dot15d4 import Dot15d4Domain
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
from whad.scapy.layers.rf4ce import RF4CE_Hdr
from struct import pack

@pb_bind(Dot15d4Domain, 'send', 1)
class SendPdu(PbPacketMessageWrapper):
    """Send Dot15d4 PDU message class
    """
    channel = PbFieldInt('dot15d4.send.channel')
    pdu = PbFieldBytes('dot15d4.send.pdu')

    def to_scapy(self):
        from whad.dot15d4.metadata import generate_dot15d4_metadata
        packet = Dot15d4(bytes(self.pdu))
        packet.metadata = generate_dot15d4_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        return cls(
            channel = packet.metadata.channel,
            pdu = bytes(packet)
        )

@pb_bind(Dot15d4Domain, 'send_raw', 1)
class SendRawPdu(PbPacketMessageWrapper):
    """Send Dot15d4 raw PDU message class
    """
    channel = PbFieldInt('dot15d4.send_raw.channel')
    pdu = PbFieldBytes('dot15d4.send_raw.pdu')
    fcs = PbFieldInt('dot15d4.send_raw.fcs')

    def to_scapy(self):
        from whad.dot15d4.metadata import generate_dot15d4_metadata
        packet = Dot15d4FCS(bytes(self.pdu))
        packet.metadata = generate_dot15d4_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        return cls(
            channel = packet.metadata.channel,
            pdu = bytes(packet)[:-2],
            fcs = packet.fcs
        )

@pb_bind(Dot15d4Domain, 'pdu', 1)
class PduReceived(PbPacketMessageWrapper):
    """Dot15d4 PDU received message class
    """
    channel = PbFieldInt('dot15d4.pdu.channel')
    pdu = PbFieldBytes('dot15d4.pdu.pdu')
    rssi = PbFieldInt('dot15d4.pdu.rssi', optional=True)
    timestamp = PbFieldInt('dot15d4.pdu.timestamp', optional=True)
    fcs_validity = PbFieldBool('dot15d4.pdu.fcs_validity', optional=True)
    lqi = PbFieldInt('dot15d4.pdu.lqi', optional=True)


    def to_scapy(self):
        from whad.dot15d4.metadata import generate_dot15d4_metadata
        packet = Dot15d4(bytes(self.pdu))
        packet.metadata = generate_dot15d4_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        return cls(
            channel = packet.metadata.channel,
            pdu = bytes(packet),
            rssi = packet.metadata.rssi,
            timestamp = packet.metadata.timestamp,
            fcs_validity = packet.metadata.is_fcs_valid,
            lqi = packet.metadata.lqi
        )

@pb_bind(Dot15d4Domain, 'raw_pdu', 1)
class RawPduReceived(PbPacketMessageWrapper):
    """Dot15d4 raw PDU received message class
    """
    channel = PbFieldInt('dot15d4.raw_pdu.channel')
    pdu = PbFieldBytes('dot15d4.raw_pdu.pdu')
    fcs = PbFieldInt('dot15d4.raw_pdu.fcs')
    rssi = PbFieldInt('dot15d4.raw_pdu.rssi', optional=True)
    timestamp = PbFieldInt('dot15d4.raw_pdu.timestamp', optional=True)
    fcs_validity = PbFieldBool('dot15d4.raw_pdu.fcs_validity', optional=True)
    lqi = PbFieldInt('dot15d4.raw_pdu.lqi', optional=True)


    def to_scapy(self):
        from whad.dot15d4.metadata import generate_dot15d4_metadata
        packet = Dot15d4FCS(bytes(self.pdu) + bytes(pack(">H", self.fcs)))
        packet.metadata = generate_dot15d4_metadata(self)
        return packet

    @classmethod
    def from_scapy(cls, packet):
        return cls(
            channel = packet.metadata.channel,
            pdu = bytes(packet)[:-2],
            fcs = packet.fcs,
            rssi = packet.metadata.rssi,
            timestamp = packet.metadata.timestamp,
            fcs_validity = packet.metadata.is_fcs_valid,
            lqi = packet.metadata.lqi
        )
