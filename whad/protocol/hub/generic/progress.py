"""WHAD Protocol Generic Progress message abstraction layer.
"""
from whad.protocol.hub import pb_bind, PbFieldInt, PbMessageWrapper
from whad.protocol.hub.generic import Generic

@pb_bind(Generic, 'progress', 1)
class Progress(PbMessageWrapper):
    """Generic progress message.
    """
    value = PbFieldInt('generic.progress.value')
