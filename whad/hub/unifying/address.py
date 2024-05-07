"""WHAD Protocol Logitech Unifying address messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from ..message import pb_bind, PbFieldBytes, PbMessageWrapper
from . import UnifyingDomain

@pb_bind(UnifyingDomain, 'set_node_addr', 1)
class SetNodeAddress(PbMessageWrapper):
    """Logitech unifying SetNodeAddress message
    """

    address = PbFieldBytes('unifying.set_node_addr.address')
