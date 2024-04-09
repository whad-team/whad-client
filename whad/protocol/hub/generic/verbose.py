"""WHAD Protocol Generic Debug message abstraction layer.
"""
from whad.protocol.hub import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper
from whad.protocol.hub.generic import Generic

@pb_bind(Generic, 'verbose', 1)
class Verbose(PbMessageWrapper):
    """Generic verbose message.
    """
    msg = PbFieldBytes('generic.verbose.data')
