"""WHAD Protocol Generic Debug message abstraction layer.
"""
from whad.hub.message import pb_bind, PbFieldBytes, PbMessageWrapper
from whad.hub.generic import Generic

@pb_bind(Generic, 'verbose', 1)
class Verbose(PbMessageWrapper):
    """Generic verbose message.
    """
    msg = PbFieldBytes('generic.verbose.data')
