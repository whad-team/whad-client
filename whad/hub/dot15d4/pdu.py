"""WHAD Protocol Dot15d4 pdu messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.hub.message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper, \
    PbFieldBool
from whad.hub.dot15d4 import Dot15d4Domain

@pb_bind(Dot15d4Domain, 'send', 1)
class SendPdu(PbMessageWrapper):
    """Send Dot15d4 PDU message class
    """
    channel = PbFieldInt('dot15d4.send.channel')
    pdu = PbFieldBytes('dot15d4.send.pdu')

@pb_bind(Dot15d4Domain, 'send_raw', 1)
class SendRawPdu(PbMessageWrapper):
    """Send Dot15d4 raw PDU message class
    """
    channel = PbFieldInt('dot15d4.send_raw.channel')
    pdu = PbFieldBytes('dot15d4.send_raw.pdu')
    fcs = PbFieldInt('dot15d4.send_raw.fcs')

@pb_bind(Dot15d4Domain, 'pdu', 1)
class PduReceived(PbMessageWrapper):
    """Dot15d4 PDU received message class
    """
    channel = PbFieldInt('dot15d4.pdu.channel')
    pdu = PbFieldBytes('dot15d4.pdu.pdu')
    rssi = PbFieldInt('dot15d4.pdu.rssi', optional=True)
    timestamp = PbFieldInt('dot15d4.pdu.timestamp', optional=True)
    fcs_validity = PbFieldBool('dot15d4.pdu.fcs_validity', optional=True)
    lqi = PbFieldInt('dot15d4.pdu.lqi', optional=True)


@pb_bind(Dot15d4Domain, 'raw_pdu', 1)
class RawPduReceived(PbMessageWrapper):
    """Dot15d4 raw PDU received message class
    """
    channel = PbFieldInt('dot15d4.raw_pdu.channel')
    pdu = PbFieldBytes('dot15d4.raw_pdu.pdu')
    fcs = PbFieldInt('dot15d4.raw_pdu.fcs')
    rssi = PbFieldInt('dot15d4.raw_pdu.rssi', optional=True)
    timestamp = PbFieldInt('dot15d4.raw_pdu.timestamp', optional=True)
    fcs_validity = PbFieldBool('dot15d4.raw_pdu.fcs_validity', optional=True)
    lqi = PbFieldInt('dot15d4.raw_pdu.lqi', optional=True)
