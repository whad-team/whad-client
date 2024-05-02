"""WHAD Protocol Dot15d4 address messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.zigbee.zigbee_pb2 import StartCmd, StopCmd
from ..message import pb_bind, PbFieldInt, PbMessageWrapper
from . import Dot15d4Domain

@pb_bind(Dot15d4Domain, 'sniff', 1)
class SniffMode(PbMessageWrapper):
    """Dot15d4 sniffing mode
    """

    channel = PbFieldInt('zigbee.sniff.channel')

@pb_bind(Dot15d4Domain, 'jam', 1)
class JamMode(PbMessageWrapper):
    """Dot15d4 jamming mode
    """

    channel = PbFieldInt('zigbee.jam.channel')

@pb_bind(Dot15d4Domain, 'end_device', 1)
class EndDeviceMode(PbMessageWrapper):
    """Dot15d4 end device mode
    """

    channel = PbFieldInt('zigbee.end_device.channel')

@pb_bind(Dot15d4Domain, 'router', 1)
class RouterMode(PbMessageWrapper):
    """Dot15d4 router mode
    """

    channel = PbFieldInt('zigbee.router.channel')

@pb_bind(Dot15d4Domain, 'coordinator', 1)
class CoordMode(PbMessageWrapper):
    """Dot15d4 coordinator mode
    """

    channel = PbFieldInt('zigbee.coordinator.channel')

@pb_bind(Dot15d4Domain, 'ed', 1)
class EnergyDetectionMode(PbMessageWrapper):
    """Dot15d4 energy detection mode
    """

    channel = PbFieldInt('zigbee.ed.channel')

@pb_bind(Dot15d4Domain, 'mitm', 1)
class MitmMode(PbMessageWrapper):
    """Dot15d4 man-in-the-middle mode
    """

    role = PbFieldInt('zigbee.mitm.role')

@pb_bind(Dot15d4Domain, 'start', 1)
class Start(PbMessageWrapper):
    """Dot15d4 start mode message class
    """
    
    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.zigbee.start.CopyFrom(StartCmd())

@pb_bind(Dot15d4Domain, 'stop', 1)
class Stop(PbMessageWrapper):
    """Dot15d4 stop mode message class
    """
    
    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.zigbee.stop.CopyFrom(StopCmd())

@pb_bind(Dot15d4Domain, 'jammed', 1)
class Jammed(PbMessageWrapper):
    """Dot15d4 Jammed notification
    """

    timestamp = PbFieldInt('zigbee.jammed.timestamp')

@pb_bind(Dot15d4Domain, 'ed_sample', 1)
class EnergyDetectionSample(PbMessageWrapper):
    """Dot15d4 Jammed notification
    """

    sample = PbFieldInt('zigbee.ed_sample.sample')
    timestamp = PbFieldInt('zigbee.ed_sample.timestamp')