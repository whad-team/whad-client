"""WHAD Protocol ESB PDU messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
#from whad.protocol.esb.esb_pb2 import StartCmd, StopCmd
from ..message import pb_bind, PbFieldBytes, PbFieldBool, PbFieldInt, PbMessageWrapper
from . import EsbDomain

@pb_bind(EsbDomain, 'send', 1)
class SendPdu(PbMessageWrapper):
    """ESB SendPdu message
    """

    channel = PbFieldInt('esb.send.channel')
    pdu = PbFieldBytes('esb.send.pdu')
    retr_count = PbFieldInt('esb.send.retransmission_count')

@pb_bind(EsbDomain, 'send_raw', 1)
class SendRawPdu(PbMessageWrapper):
    """ESB SendRawPdu message
    """

    channel = PbFieldInt('esb.send_raw.channel')
    pdu = PbFieldBytes('esb.send_raw.pdu')
    retr_count = PbFieldInt('esb.send_raw.retransmission_count')

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