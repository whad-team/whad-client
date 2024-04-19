"""WHAD Protocol Generic Progress message abstraction layer.
"""
from whad.hub.message import pb_bind, PbFieldInt, PbMessageWrapper
from whad.hub.generic import Generic

@pb_bind(Generic, 'progress', 1)
class Progress(PbMessageWrapper):
    """Generic progress message.
    """
    value = PbFieldInt('generic.progress.value')
