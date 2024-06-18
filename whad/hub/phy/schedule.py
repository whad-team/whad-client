"""WHAD Protocol PHY schedule packet messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from ..message import pb_bind, PbFieldInt, PbFieldBytes, PbFieldBool, PbMessageWrapper
from . import PhyDomain

from .timestamp import Timestamp

@pb_bind(PhyDomain, 'sched_send', 1)
class SchedulePacket(PbMessageWrapper):
    """PHY schedule packet send message
    """

    packet = PbFieldBytes('phy.sched_send.packet')
    timestamp = PbFieldInt('phy.sched_send.timestamp')

@pb_bind(PhyDomain, 'sched_pkt_rsp', 1)
class SchedulePacketResponse(PbMessageWrapper):
    """PHY schedule packet response message
    """

    id = PbFieldInt('phy.sched_pkt_rsp.id')
    full = PbFieldBool('phy.sched_pkt_rsp.full', optional=True)

@pb_bind(PhyDomain, 'sched_pkt_sent', 1)
class ScheduledPacketSent(PbMessageWrapper):
    """PHY schedule packet sent notification message
    """

    id = PbFieldInt('phy.sched_pkt_sent.id')
