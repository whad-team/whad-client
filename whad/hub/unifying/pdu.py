"""WHAD Protocol Logitech Unifying PDU messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from ..message import pb_bind, PbFieldBytes, PbFieldBool, PbFieldInt, PbMessageWrapper
from . import UnifyingDomain

@pb_bind(UnifyingDomain, 'send', 1)
class SendPdu(PbMessageWrapper):
    """ESB SendPdu message
    """

    channel = PbFieldInt('unifying.send.channel')
    pdu = PbFieldBytes('unifying.send.pdu')
    retr_count = PbFieldInt('unifying.send.retransmission_count')

@pb_bind(UnifyingDomain, 'send_raw', 1)
class SendRawPdu(PbMessageWrapper):
    """ESB SendRawPdu message
    """

    channel = PbFieldInt('unifying.send_raw.channel')
    pdu = PbFieldBytes('unifying.send_raw.pdu')
    retr_count = PbFieldInt('unifying.send_raw.retransmission_count')

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