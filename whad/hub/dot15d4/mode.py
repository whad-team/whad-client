"""WHAD Protocol Dot15d4 address messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.dot15d4.dot15d4_pb2 import StartCmd, StopCmd
from whad.hub.events import JammedEvt
from ..message import pb_bind, PbFieldInt, PbMessageWrapper
from . import Dot15d4Domain

@pb_bind(Dot15d4Domain, 'sniff', 1)
class SniffMode(PbMessageWrapper):
    """Dot15d4 sniffing mode
    """

    channel = PbFieldInt('dot15d4.sniff.channel')

@pb_bind(Dot15d4Domain, 'jam', 1)
class JamMode(PbMessageWrapper):
    """Dot15d4 jamming mode
    """

    channel = PbFieldInt('dot15d4.jam.channel')

@pb_bind(Dot15d4Domain, 'end_device', 1)
class EndDeviceMode(PbMessageWrapper):
    """Dot15d4 end device mode
    """

    channel = PbFieldInt('dot15d4.end_device.channel')

@pb_bind(Dot15d4Domain, 'router', 1)
class RouterMode(PbMessageWrapper):
    """Dot15d4 router mode
    """

    channel = PbFieldInt('dot15d4.router.channel')

@pb_bind(Dot15d4Domain, 'coordinator', 1)
class CoordMode(PbMessageWrapper):
    """Dot15d4 coordinator mode
    """

    channel = PbFieldInt('dot15d4.coordinator.channel')

@pb_bind(Dot15d4Domain, 'ed', 1)
class EnergyDetectionMode(PbMessageWrapper):
    """Dot15d4 energy detection mode
    """

    channel = PbFieldInt('dot15d4.ed.channel')

@pb_bind(Dot15d4Domain, 'mitm', 1)
class MitmMode(PbMessageWrapper):
    """Dot15d4 man-in-the-middle mode
    """

    role = PbFieldInt('dot15d4.mitm.role')

@pb_bind(Dot15d4Domain, 'start', 1)
class Start(PbMessageWrapper):
    """Dot15d4 start mode message class
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.dot15d4.start.CopyFrom(StartCmd())

@pb_bind(Dot15d4Domain, 'stop', 1)
class Stop(PbMessageWrapper):
    """Dot15d4 stop mode message class
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.dot15d4.stop.CopyFrom(StopCmd())

@pb_bind(Dot15d4Domain, 'jammed', 1)
class Jammed(PbMessageWrapper):
    """Dot15d4 Jammed notification
    """

    timestamp = PbFieldInt('dot15d4.jammed.timestamp')

    def to_event(self) -> JammedEvt:
        """Convert this message into a WHAD event.
        """
        return JammedEvt(
            timestamp=self.timestamp
        )
    
    @staticmethod
    def from_event(event):
        """Convert an event into a message.
        """
        return Jammed(
            timestamp=event.timestamp
        )

@pb_bind(Dot15d4Domain, 'ed_sample', 1)
class EnergyDetectionSample(PbMessageWrapper):
    """Dot15d4 Jammed notification
    """

    sample = PbFieldInt('dot15d4.ed_sample.sample')
    timestamp = PbFieldInt('dot15d4.ed_sample.timestamp')
