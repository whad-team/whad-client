from whad.protocol.whad_pb2 import Message
from whad.protocol.ant.ant_pb2 import StartCmd, StopCmd
from whad.hub.events import JammedEvt
from ..message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper
from . import AntDomain


@pb_bind(AntDomain, 'sniff', 3)
class SniffMode(PbMessageWrapper):
    """ANT sniffing mode
    """
    frequency = PbFieldInt('ant.sniff.frequency')
    network_key = PbFieldBytes('ant.sniff.network_key')
    device_number = PbFieldInt('ant.sniff.device_number', optional=True)
    device_type = PbFieldInt('ant.sniff.device_type', optional=True)
    transmission_type = PbFieldInt('ant.sniff.transmission_type', optional=True)
    


@pb_bind(AntDomain, 'jam', 3)
class JamMode(PbMessageWrapper):
    """ANT jamming mode
    """
    frequency = PbFieldInt('ant.jam.frequency')


@pb_bind(AntDomain, 'master_mode', 3)
class MasterMode(PbMessageWrapper):
    """ANT master mode
    """
    channel_number = PbFieldInt('ant.master_mode.channel_number')


@pb_bind(AntDomain, 'slave_mode', 3)
class SlaveMode(PbMessageWrapper):
    """ANT slave mode
    """
    channel_number = PbFieldInt('ant.slave_mode.channel_number')



@pb_bind(AntDomain, 'start', 3)
class Start(PbMessageWrapper):
    """ANT start mode message
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.ant.start.CopyFrom(StartCmd())



@pb_bind(AntDomain, 'stop', 3)
class Stop(PbMessageWrapper):
    """ANT stop mode message
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.ant.stop.CopyFrom(StopCmd())


@pb_bind(AntDomain, 'jammed', 3)
class Jammed(PbMessageWrapper):
    """ANT Jammed notification
    """

    timestamp = PbFieldInt('ant.jammed.timestamp')

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