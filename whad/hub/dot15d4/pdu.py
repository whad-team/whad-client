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
    channel = PbFieldInt('zigbee.send.channel')
    pdu = PbFieldBytes('zigbee.send.pdu')

@pb_bind(Dot15d4Domain, 'send_raw', 1)
class SendRawPdu(PbMessageWrapper):
    """Send Dot15d4 raw PDU message class
    """
    channel = PbFieldInt('zigbee.send_raw.channel')
    pdu = PbFieldBytes('zigbee.send_raw.pdu')
    fcs = PbFieldInt('zigbee.send_raw.fcs')

@pb_bind(Dot15d4Domain, 'pdu', 1)
class PduReceived(PbMessageWrapper):
    """Dot15d4 PDU received message class
    """
    channel = PbFieldInt('zigbee.pdu.channel')
    pdu = PbFieldBytes('zigbee.pdu.pdu')
    rssi = PbFieldInt('zigbee.pdu.rssi', optional=True)
    timestamp = PbFieldInt('zigbee.pdu.timestamp', optional=True)
    fcs_validity = PbFieldBool('zigbee.pdu.fcs_validity', optional=True)
    lqi = PbFieldInt('zigbee.pdu.lqi', optional=True)


@pb_bind(Dot15d4Domain, 'raw_pdu', 1)
class RawPduReceived(PbMessageWrapper):
    """Dot15d4 raw PDU received message class
    """
    channel = PbFieldInt('zigbee.raw_pdu.channel')
    pdu = PbFieldBytes('zigbee.raw_pdu.pdu')
    fcs = PbFieldInt('zigbee.raw_pdu.fcs')
    rssi = PbFieldInt('zigbee.raw_pdu.rssi', optional=True)
    timestamp = PbFieldInt('zigbee.raw_pdu.timestamp', optional=True)
    fcs_validity = PbFieldBool('zigbee.raw_pdu.fcs_validity', optional=True)
    lqi = PbFieldInt('zigbee.raw_pdu.lqi', optional=True)
    