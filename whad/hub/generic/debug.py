"""WHAD Protocol Generic Debug message abstraction layer.
"""
from whad.hub.message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper
from whad.hub.generic import Generic

@pb_bind(Generic, 'debug', 1)
class Debug(PbMessageWrapper):
    """Generic debug message.
    """
    level = PbFieldInt('generic.debug.level')
    msg = PbFieldBytes('generic.debug.data')
