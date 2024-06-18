"""WHAD Protocol PHY mode messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.phy.phy_pb2 import MonitorCmd, StartCmd, StopCmd
from ..message import pb_bind, PbFieldInt, PbFieldBool, PbFieldArray, PbMessageWrapper
from . import PhyDomain

from .timestamp import Timestamp

@pb_bind(PhyDomain, 'sniff', 1)
class SniffMode(PbMessageWrapper):
    """PHY Sniff mode message
    """

    iq_stream = PbFieldBool('phy.sniff.iq_stream', optional=True)

@pb_bind(PhyDomain, 'jam', 1)
class JamMode(PbMessageWrapper):
    """PHY Jam mode message
    """

    mode = PbFieldInt('phy.jam.mode')

@pb_bind(PhyDomain, 'jammed', 1)
class Jammed(PbMessageWrapper):
    """PHY Jammed notification message
    """

    timestamp = PbFieldInt('phy.jammed.timestamp')

@pb_bind(PhyDomain, 'monitor', 1)
class MonitorMode(PbMessageWrapper):
    """PHY Monitor mode message
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.phy.monitor.CopyFrom(MonitorCmd())

@pb_bind(PhyDomain, 'monitor_report', 1)
class MonitoringReport(PbMessageWrapper):
    """PHY monitoring report notification message
    """

    timestamp = PbFieldInt('phy.monitor_report.timestamp')
    reports = PbFieldArray('phy.monitor_report.report')

@pb_bind(PhyDomain, 'start', 1)
class Start(PbMessageWrapper):
    """PHY Start mode message
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.phy.start.CopyFrom(StartCmd())

@pb_bind(PhyDomain, 'stop', 1)
class Stop(PbMessageWrapper):
    """PHY Stop mode message
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.phy.stop.CopyFrom(StopCmd())