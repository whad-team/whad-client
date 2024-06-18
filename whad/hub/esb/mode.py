"""WHAD Protocol ESB mode messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.esb.esb_pb2 import StartCmd, StopCmd
from whad.hub.events import JammedEvt
from ..message import pb_bind, PbFieldBytes, PbFieldBool, PbFieldInt, PbMessageWrapper
from . import EsbDomain

@pb_bind(EsbDomain, 'sniff', 1)
class SniffMode(PbMessageWrapper):
    """ESB SniffMode message
    """

    channel = PbFieldInt('esb.sniff.channel')
    address = PbFieldBytes('esb.sniff.address')
    show_acks = PbFieldBool('esb.sniff.show_acknowledgements')

@pb_bind(EsbDomain, 'jam', 1)
class JamMode(PbMessageWrapper):
    """ESB JamMode message
    """

    channel = PbFieldInt('esb.jam.channel')

@pb_bind(EsbDomain, 'jammed', 1)
class Jammed(PbMessageWrapper):
    """ESB Jammed notification message
    """

    timestamp = PbFieldInt('esb.jammed.timestamp')

    def to_event(self):
        """Convert this message into a WHAD event.
        """
        return JammedEvt(
            timestamp=self.timestamp
        )
    
    @staticmethod
    def from_event(event):
        """Create a Jammed message from event.
        """
        return Jammed(timestamp=event.timestamp)

@pb_bind(EsbDomain, 'start', 1)
class EsbStart(PbMessageWrapper):
    """ESB EsbStart message
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.esb.start.CopyFrom(StartCmd())

@pb_bind(EsbDomain, 'stop', 1)
class EsbStop(PbMessageWrapper):
    """ESB EsbStop message
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.esb.stop.CopyFrom(StopCmd())

@pb_bind(EsbDomain, 'prx', 1)
class PrxMode(PbMessageWrapper):
    """ESB PrxMode message
    """

    channel = PbFieldInt('esb.prx.channel')

@pb_bind(EsbDomain, 'ptx', 1)
class PtxMode(PbMessageWrapper):
    """ESB PtxMode message
    """

    channel = PbFieldInt('esb.ptx.channel')