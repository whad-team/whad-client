from whad.protocol.whad_pb2 import Message
from whad.protocol.ant.ant_pb2 import StartCmd, StopCmd
from whad.hub.events import JammedEvt
from ..message import pb_bind, PbFieldInt, PbMessageWrapper
from . import AntDomain


@pb_bind(AntDomain, 'sniff', 1)
class SniffMode(PbMessageWrapper):
    """Dot15d4 sniffing mode
    """

    channel = PbFieldInt('dot15d4.sniff.channel')
