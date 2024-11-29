"""WHAD Protocol Dot15d4 TSCH-related messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.dot15d4.dot15d4_pb2 import SyncCmd
from ..message import pb_bind, PbFieldInt, PbMessageWrapper
from . import Dot15d4Domain

@pb_bind(Dot15d4Domain, 'sync', 2)
class Sync(PbMessageWrapper):
    """Dot15d4 synchronization
    """

    timestamp = PbFieldInt('dot15d4.sync.timestamp')
    asn = PbFieldInt('dot15d4.sync.asn')